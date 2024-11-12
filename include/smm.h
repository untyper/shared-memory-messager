// Copyright (c) [2024] [Jovan J. E. Odassius]
//
// License: MIT (See the LICENSE file in the root directory)
// Github: https://github.com/untyper/shared-memory-messager

#pragma once

// C/C++ includes
#include <string>
#include <functional>
#include <utility>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <condition_variable>

// Windows includes
#include <Windows.h>
//#include <winapifamily.h>

// NOTES:
// - To use this in a UWP app, define SMM_UWP
// 
// - Each messaging channel only has one message 'slot' which is continually being read from.
//   All synchronization to make sure the messages are delivered properly is performed by the sender instead.
//   By doing it this way, we avoid complex queuing logic on the shared memory space,
//   although this method does come with it's own limitations too.
//
// - No Linux support. To support linux, implement event logic with Linux semaphores. TODOs...

#ifdef GetObject
#undef GetObject
#endif

#define PAGE_SIZE 4096
#define MAX_SEND_ATTEMPTS 4

namespace smm
{

#ifdef SMM_UWP
// Helper to convert std::string to std::string for UWP specifics
std::wstring string_to_wstring(const std::string& utf8_string);
#endif

template <typename T>
class Message_Queue
{
private:
  struct Node
  {
    std::unique_ptr<T> data;
    std::atomic<Node*> next;

    Node() : data(nullptr), next(nullptr) {}

    template <typename U>
    explicit Node(U&& value)
      : data(std::make_unique<T>(std::forward<U>(value))), next(nullptr) {}
  };

  std::atomic<int> node_count = 0;
  std::atomic<Node*> tail;
  Node* head;

  // For cleaning up any existing nodes in the current queue upon exiting
  void clear_nodes()
  {
    Node* current = this->head;

    while (current)
    {
      Node* next_node = current->next.load(std::memory_order_relaxed);
      delete current;
      current = next_node;
    }
  }

public:
  // Return current size of the queue
  int size()
  {
    return this->node_count.load();
  }

  // Enqueue function accepting both copyable and movable types
  template <typename U>
  void enqueue(U&& value)
  {
    Node* new_node = new Node(std::forward<U>(value));
    Node* prev_tail = this->tail.exchange(new_node, std::memory_order_acq_rel);
    prev_tail->next.store(new_node, std::memory_order_release);
    this->node_count.fetch_add(1); // Increment size counter
  }

  // Consumer calls this to dequeue data
  std::unique_ptr<T> dequeue()
  {
    Node* next_node = this->head->next.load(std::memory_order_acquire);

    if (!next_node)
    {
      return nullptr; // Queue is empty
    }

    std::unique_ptr<T> result = std::move(next_node->data);
    delete this->head;
    this->head = next_node;

    // Decrement size counter and return queued entry
    this->node_count.fetch_sub(1);
    return result;
  }

  // Disable copy assignment operator
  Message_Queue& operator=(const Message_Queue&) = delete;

  // Move assignment operator
  Message_Queue& operator=(Message_Queue&& other) noexcept
  {
    // Avoid self-assignment
    if (this != &other)
    {
      this->clear_nodes();

      // Transfer ownership of nodes
      node_count.store(other.node_count.load());
      tail.store(other.tail.load(std::memory_order_relaxed), std::memory_order_relaxed);
      this->head = other.head;

      // Reset other to indicate moved-from state
      other.node_count.store(0);
      other.tail.store(nullptr, std::memory_order_relaxed);
      other.head = nullptr;
    }

    return *this;
  }

  // Disable copy constructor
  Message_Queue(const Message_Queue&) = delete;

  // Move constructor
  Message_Queue(Message_Queue&& other) noexcept :
    node_count(other.node_count.load()),
    tail(other.tail.load(std::memory_order_relaxed)),
    head(other.head)
  {
    other.node_count.store(0);
    other.tail.store(nullptr, std::memory_order_relaxed);
    other.head = nullptr;
  }

  Message_Queue()
  {
    // Create a dummy node to simplify enqueue/dequeue logic
    Node* dummy = new Node();
    this->head = dummy;
    this->tail.store(dummy, std::memory_order_relaxed);
  }

  ~Message_Queue()
  {
    this->clear_nodes();
  }
};

// Base class for all messages.
// Use this to discern type of message before
// casting the buffer to the correct type for reading...
struct Message
{
  UINT type = 0; // 4 bytes
  CHAR content[PAGE_SIZE - sizeof(UINT)] = {0};
  // Total content size should be equal to
  // a standard page size i.e. ~4096 bytes

  UINT get_type()
  {
    return this->type;
  }

  template <typename T>
  T get_content_as()
  {
    return *reinterpret_cast<T*>(this->content);
  }

  template <typename T>
  void set_content_as(UINT type, T content)
  {
    this->type = type;
    *reinterpret_cast<T*>(this->content) = content;
  }

  // Constructors
  template <typename T>
  Message(UINT type, T content)
  {
    this->set_content_as(type, content);
  }

  Message() {}
};

class Message_Object
{
private:
  std::string name;
  HANDLE object = NULL;

public:
  std::string& get_name();
  HANDLE& get_object();
};

using Message_Event = Message_Object;

class Message_Mapping : public Message_Object
{
private:
  PVOID address = NULL; // byte to byte file mapping object's address

public:
  PVOID& get_address();
};

class Messaging_Channel
{
protected:
  // True if CreateEventObject() and CreateMapping() both succeed, false otherwise
  bool channel_created = false;
  std::string id;

  Message_Event sent;
  Message_Event emptied;
  Message_Mapping mapping;

  // Member functions below
  bool create_event_objects();
  bool create_mapping();
  void create_channel(std::string id);

public:
  bool is_channel_created();
  const std::string& get_id();
  void close();

  Messaging_Channel(std::string id);
  Messaging_Channel() {}
};

class Message_Receiver : public Messaging_Channel
{
public:
  // Getters
  Message_Event& get_sent_event();
  Message_Event& get_emptied_event();
  Message_Mapping& get_mapping();

  void open(std::string id);

  Message_Receiver(std::string id);
  Message_Receiver() {}
};

struct Message_Info
{
  Message_Receiver receiver;
  Message message;
  std::atomic<int> send_attempts = 0;

  // Compiler won't generate move/copy semantics for us so we must do it ourselves
  Message_Info& operator=(Message_Info&& other) noexcept;
  Message_Info& operator=(const Message_Info& other);

  Message_Info(Message_Info&& other) noexcept;
  Message_Info(const Message_Info& other);
  Message_Info(Message_Receiver receiver, Message data);
  Message_Info() {}
};

class Message_Client : public Messaging_Channel
{
protected:
  std::thread sender_thread;
  std::thread receiver_thread;

  std::atomic<bool> is_sender_thread_running = false;
  std::atomic<bool> is_receiver_thread_running = false;
  std::atomic<int> max_send_attempts = MAX_SEND_ATTEMPTS;

  Message_Event enqueued;
  Message_Queue<Message_Info> send_queue;
  std::function<void(Message)> handler;

  // Member functions below
  bool create_enqueue_signaling(std::string id);
  bool send_enqueued_signal();
  void wait_for_enqueued_signal();

  void sender_loop();
  void receiver_loop();
  void start_sender_loop();
  void start_receiver_loop();

public:
  bool is_thread_running();
  void send(Message_Receiver receiver, Message data);
  void set_handler(std::function<void(Message)> handler);
  void create(std::string id, std::function<void(Message)> handler = nullptr);
  void close(); // Override

  Message_Client& operator=(const Message_Client&) = delete;
  Message_Client& operator=(Message_Client&& other) noexcept;

  Message_Client(const Message_Client&) = delete;
  Message_Client(Message_Client&& other) noexcept;
  Message_Client(std::string id, std::function<void(Message)> handler = nullptr);
  Message_Client() {};
  ~Message_Client();
};

// ********** Definitions **********

#ifdef SMM_UWP
inline std::wstring string_to_wstring(const std::string& utf8_string)
{
  // Determine the size of the resulting wide string
  int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8_string.c_str(), -1, NULL, 0);

  // Create a wide string to hold the converted result
  std::wstring wide_string(size_needed - 1, 0); // size_needed includes null terminator, so exclude it

  // Perform the conversion
  MultiByteToWideChar(CP_UTF8, 0, utf8_string.c_str(), -1, &wide_string[0], size_needed);

  return wide_string;
}
#endif

inline std::string& Message_Object::get_name()
{
  return this->name;
}

inline HANDLE& Message_Object::get_object()
{
  return this->object;
}

inline PVOID& Message_Mapping::get_address()
{
  return this->address;
}

// Member functions below
inline bool Messaging_Channel::create_event_objects()
{
  if (!(this->sent.get_object() = CreateEventA(NULL, FALSE, FALSE, this->sent.get_name().data())))
  {
    return false; // Failed to create event object
  }

  if (!(this->emptied.get_object() = CreateEventA(NULL, FALSE, TRUE, this->emptied.get_name().data())))
  {
    return false; // Failed to create event object
  }

  // Successfully created event objects.
  // We can now send signals to other processes.
  return true;
}

inline bool Messaging_Channel::create_mapping()
{
  // We are using INVALID_HANDLE_VALUE for handle to use a mapping object
  // backed by a system paging file so that we don't have to create a file manually

  ULONG64 size = sizeof(Message); // In bytes
  HANDLE& mapping_object = this->mapping.get_object();

#ifdef SMM_UWP
  if (!(mapping_object = CreateFileMappingFromApp(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, size, string_to_wstring(this->mapping.get_name()).data())))
#else
  if (!(mapping_object = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size, this->mapping.get_name().data())))
#endif
  {
    return false; // Failed to create mapping object
  }

#ifdef SMM_UWP
  if (!(this->mapping.get_address() = MapViewOfFileFromApp(mapping_object, FILE_MAP_ALL_ACCESS, 0, 0)))
#else
  if (!(this->mapping.get_address() = MapViewOfFile(mapping_object, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
#endif
  {
    CloseHandle(mapping_object);
    return false; // Failed to map to memory
  }

  // Successfully mapped file to memory.
  // We should now have 'shared memory' communication ready to go.
  return true;
}

// Getter to check if event and mapping stuff have been created successfully
inline bool Messaging_Channel::is_channel_created()
{
  return this->channel_created;
}

inline const std::string& Messaging_Channel::get_id()
{
  return this->id;
}

// Create communication channel (event object and shared memory)
// This should only be called once.
// Check is_channel_created() to see if that's the case.
inline void Messaging_Channel::create_channel(std::string id)
{
  this->mapping.get_name() = id + ".mapping";
  this->sent.get_name() = id + ".event";
  this->emptied.get_name() = id + ".emptied";

  if (this->create_mapping() && this->create_event_objects())
  {
    this->channel_created = true;
    this->id = id;
  }
}

inline void Messaging_Channel::close()
{
  PVOID& mapping_address = this->mapping.get_address();
  HANDLE& mapping_object = this->mapping.get_object();
  HANDLE& sent_object = this->sent.get_object();
  HANDLE& emptied_object = this->emptied.get_object();

  // TODO: Some error checking?
  // Release handles and unmap shared memory
  UnmapViewOfFile(mapping_address);
  CloseHandle(mapping_object);
  CloseHandle(sent_object);
  CloseHandle(emptied_object);

  // Reset to NULL in case we want to reuse the object with another client channel
  mapping_address = mapping_object = sent_object = emptied_object = NULL;

  // Clear the names too. Maybe unnecessary?
  this->mapping.get_name().clear();
  this->sent.get_name().clear();
  this->emptied.get_name().clear();
}

// Constructor. ID must be unique
inline Messaging_Channel::Messaging_Channel(std::string id)
{
  this->create_channel(id);
}

// Getters
inline Message_Event& Message_Receiver::get_sent_event()
{
  return this->sent;
}

inline Message_Event& Message_Receiver::get_emptied_event()
{
  return this->emptied;
}

inline Message_Mapping& Message_Receiver::get_mapping()
{
  return this->mapping;
}

inline void Message_Receiver::open(std::string id)
{
  this->create_channel(id);
}

// Constructor. ID must be unique
inline Message_Receiver::Message_Receiver(std::string id)
{
  this->open(id);
}

// Move assignment operator
inline Message_Info& Message_Info::operator=(Message_Info&& other) noexcept
{
  // Avoid self-assignment
  if (this != &other)
  {
    receiver = std::move(other.receiver);
    message = std::move(other.message);
    send_attempts.store(other.send_attempts.load());

    // Reset other to indicate moved-from state
    other.send_attempts.store(0);
  }

  return *this;
}

// Copy assignment operator
inline Message_Info& Message_Info::operator=(const Message_Info& other)
{
  // Avoid self-assignment
  if (this != &other)
  {
    receiver = other.receiver;
    message = other.message;
    send_attempts.store(other.send_attempts.load()); // Copy the value of `send_attempts`
  }

  return *this;
}

// Move constructor
inline Message_Info::Message_Info(Message_Info&& other) noexcept :
  receiver(std::move(other.receiver)),
  message(std::move(other.message))
{
  send_attempts.store(other.send_attempts.load());

  // Reset other to indicate moved-from state
  other.send_attempts.store(0);
}

// Copy constructor
inline Message_Info::Message_Info(const Message_Info& other) :
  receiver(other.receiver),
  message(other.message),
  send_attempts(other.send_attempts.load())
{
}

inline Message_Info::Message_Info(Message_Receiver receiver, Message data) :
  receiver(std::move(receiver)),
  message(std::move(data))
{
}

inline bool Message_Client::create_enqueue_signaling(std::string id)
{
  this->enqueued.get_name() = id + ".i_event"; // Internal event

  if (!(this->enqueued.get_object() = CreateEventA(NULL, FALSE, FALSE, this->enqueued.get_name().data())))
  {
    return false; // Failed to create event object
  }
}

inline bool Message_Client::send_enqueued_signal()
{
  return SetEvent(this->enqueued.get_object());
}

inline void Message_Client::wait_for_enqueued_signal()
{
  WaitForSingleObject(this->enqueued.get_object(), INFINITE);
}

// Pulls out data from the to-be-sent queue to finally send the message to the user-specified receiver.
// This function runs on its own thread.
inline void Message_Client::sender_loop()
{
  while (this->is_sender_thread_running)
  {
    auto result = this->send_queue.dequeue();

    if (!result) // Queue is empty
    {
      // Wait until the queue contains an entry so we don't iterate unnecessarily
      this->wait_for_enqueued_signal();

      // enqueue() has been called and there should now be an entry in the queue.
      // Skip to next iteration to process it
      continue;
    }

    auto& queued = *result;
    auto& receiver = queued.receiver;

    if (WaitForSingleObject(receiver.get_emptied_event().get_object(), NULL) == WAIT_TIMEOUT)
    {
      // We are keeping track of send attempts so we can discard un-sendable messages
      // after a user specified amount of tries.
      // This necessary to avoid excessive busy waiting (waiting for the receiver to clear their message slot)

      // If send max send attempts reached, don't queue message for a retry.
      // This will cause the message to be forever lost
      if (queued.send_attempts.load() >= this->max_send_attempts.load())
      {
        continue;
      }

      // Otherwise continue retrying until max attempts is reached
      queued.send_attempts.fetch_add(1);
      this->send_queue.enqueue(std::move(queued));
      continue;

      // Alternatives:
      // Create a low priority thread with a queue of failed messages which attempts to send
      // the failed messages over a larger delay (to avoid excessive CPU consumption on failed messages)
    }

    // No timeout: Message channel is clear and ready for new messages

    // Fill shared memory with the next enqueued item
    *reinterpret_cast<Message*>(receiver.get_mapping().get_address()) = queued.message;

    // Signal the other process that data is ready
    SetEvent(receiver.get_sent_event().get_object());
  }
}

// Main message loop for this client.
// This function waits for messages from other processes, dereferences them
// and relays them to the user-specified message handler.
inline void Message_Client::receiver_loop()
{
  while (this->is_receiver_thread_running)
  {
    if (this->handler)
    {
      // Wait for a message
      WaitForSingleObject(this->sent.get_object(), INFINITE);

      // Read shared memory into a message object
      auto message = *reinterpret_cast<Message*>(this->mapping.get_address());

      // Now pass the message object to our
      // message handler (user-specified) for further processing
      this->handler(message);

      // Signal the other process that the message has been read.
      SetEvent(this->emptied.get_object());
    }
  }
}

inline void Message_Client::start_sender_loop()
{
  // Only spawn a new thread if not already running
  if (!this->is_sender_thread_running)
  {
    this->is_sender_thread_running = true;
    this->sender_thread = std::thread(&Message_Client::sender_loop, this);
  }
}

inline void Message_Client::start_receiver_loop()
{
  // Only spawn a new thread if not already running
  if (!this->is_receiver_thread_running)
  {
    this->is_receiver_thread_running = true;
    this->receiver_thread = std::thread(&Message_Client::receiver_loop, this);
  }
}

// Use this in combination with is_channel_created() to (for example)
// check if the current client object can be reassigned to a new channel
inline bool Message_Client::is_thread_running()
{
  return (this->is_sender_thread_running && this->is_receiver_thread_running);
}

// This function adds data to our to-be-sent queue
inline void Message_Client::send(Message_Receiver receiver, Message data)
{
  this->send_queue.enqueue(Message_Info{receiver, data});
  this->send_enqueued_signal();
}

// Function for assigning a user-specified message handler.
// Automatically starts the message thread if it doesn't exist already.
inline void Message_Client::set_handler(std::function<void(Message)> handler)
{
  this->handler = handler;
  this->start_receiver_loop();
}

inline void Message_Client::create(std::string id, std::function<void(Message)> handler)
{
  this->create_enqueue_signaling(id);
  this->create_channel(id);
  this->start_sender_loop();

  if (handler != nullptr)
  {
    this->set_handler(handler);
  }
}

// Close channel (for example) before reassigning to a new channel
inline void Message_Client::close()
{
  // Wait until all messages in the message queue are sent
  while (this->send_queue.size() != 0)
  {
    Sleep(10);
  }

  // Unmap file memory and close all handles
  Messaging_Channel::close();

  // Signal to message threads to terminate
  this->is_sender_thread_running = false;
  this->is_receiver_thread_running = false;

  // Join threads with main thread
  this->sender_thread.join();
  this->receiver_thread.join();
}

// Move assignment operator
inline Message_Client& Message_Client::operator=(Message_Client&& other) noexcept
{
  // Avoid self-assignment
  if (this != &other)
  {
    Messaging_Channel::operator=(std::move(other));
    sender_thread = std::move(other.sender_thread);
    receiver_thread = std::move(other.receiver_thread);
    enqueued = std::move(other.enqueued);
    send_queue = std::move(other.send_queue);
    handler = std::move(other.handler);

    is_sender_thread_running.store(other.is_sender_thread_running.load());
    is_receiver_thread_running.store(other.is_receiver_thread_running.load());
    max_send_attempts.store(other.max_send_attempts.load());

    // Reset other to indicate moved-from state
    other.is_sender_thread_running.store(false);
    other.is_receiver_thread_running.store(false);
    other.max_send_attempts.store(0);
  }

  return *this;
}

// Move constructor
inline Message_Client::Message_Client(Message_Client&& other) noexcept :
  Messaging_Channel(std::move(other)),
  sender_thread(std::move(other.sender_thread)),
  receiver_thread(std::move(other.receiver_thread)),
  enqueued(std::move(other.enqueued)),
  send_queue(std::move(other.send_queue)),
  handler(std::move(other.handler))
{
  is_sender_thread_running.store(other.is_sender_thread_running.load());
  is_receiver_thread_running.store(other.is_receiver_thread_running.load());
  max_send_attempts.store(other.max_send_attempts.load());

  // Reset other to indicate moved-from state
  other.is_sender_thread_running.store(false);
  other.is_receiver_thread_running.store(false);
  other.max_send_attempts.store(0);
}

// Constructor. ID must be unique
inline Message_Client::Message_Client(std::string id, std::function<void(Message)> handler)
{
  this->create(id, handler);
}

inline Message_Client::~Message_Client()
{
  this->close();
}

} // namespace smm
