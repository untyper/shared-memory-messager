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

// NOTE:
// Each Message_Client only has one message 'slot'.
// This means that if multiple processes were to send a message
// to the same client at the same time before the client could handle either,
// there *could* be a race condition in which the newer message overwrites the earlier one.
// In other words, for now, it's only safe for a client to communicate with one receiver process at a time.
// ...Unless of course, there has been a misunderstanding about the functionality of WaitForSingleObject...

// TODO:
// Implement thread-safe queuing logic inside the shared memory to solve the noted problem above.

// NOTE:
// Channel = Event handles and mapped files that comprise the communication mechanism

#ifdef GetObject
#undef GetObject
#endif

#define PAGE_SIZE 4096

namespace smm
{

// Helper to convert std::string to std::string for UWP specifics
std::wstring string_to_wstring(const std::string& utf8String);

// Ref: stackoverflow.com/a/16075550
// A threadsafe-queue.
template <class T>
class Message_Queue
{
private:
  std::queue<T> queue;
  mutable std::mutex mutex;
  std::condition_variable condition;

public:
  // Add an element to the queue.
  void enqueue(T t)
  {
    std::lock_guard<std::mutex> lock(this->mutex);
    this->queue.push(t);
    this->condition.notify_one();
  }

  // Get the "front"-element.
  // If the queue is empty, wait till an element is available.
  T dequeue()
  {
    std::unique_lock<std::mutex> lock(this->mutex);
    this->condition.wait(lock, [&] { return !this->queue.empty(); });

    T value = this->queue.front();
    this->queue.pop();
    return value;
  }

  // Clear the queue.
  void clear()
  {
    std::lock_guard<std::mutex> lock(this->mutex);
    this->queue = {};
    this->condition.notify_one();
  }

  bool is_empty()
  {
    std::lock_guard<std::mutex> lock(this->mutex);
    bool empty = this->queue.empty();
    this->condition.notify_one();
    return empty;
  }

  Message_Queue() : queue(), mutex(), condition() {}
  ~Message_Queue() {}
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

  template <typename ContentType>
  ContentType get_content_as()
  {
    return *reinterpret_cast<ContentType*>(this->content);
  }

  template <typename ContentType>
  void set_content_as(UINT type, ContentType content)
  {
    this->type = type;
    *reinterpret_cast<ContentType*>(this->content) = content;
  }

  // Templates on a constructor? :o
  template <typename ContentType>
  Message(UINT type, ContentType content)
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

  // Constructors
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
};

class Message_Client : public Messaging_Channel
{
protected:
  std::thread sender_thread;
  std::thread receiver_thread;

  std::atomic<bool> is_sender_thread_running = false;
  std::atomic<bool> is_receiver_thread_running = false;

  Message_Queue<Message_Info> send_queue;
  std::function<void(Message)> handler;

  // Member functions below
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

  Message_Client(std::string id, std::function<void(Message)> handler = nullptr);
  Message_Client() {};
  ~Message_Client();
};

} // namespace smm
