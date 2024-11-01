// Copyright (c) [2024] [Jovan J. E. Odassius]
//
// License: MIT (See the LICENSE file in the root directory)
// Github: https://github.com/untyper/shared-memory-messager

#include "smm.h"

std::wstring& Message_Object::get_name()
{
  return this->name;
}

HANDLE& Message_Object::get_object()
{
  return this->object;
}

PVOID& Message_Mapping::get_address()
{
  return this->address;
}

// Member functions below
bool Messaging_Channel::create_event_objects()
{
  if (!(this->sent.get_object() = CreateEvent(NULL, FALSE, FALSE, this->sent.get_name().data())))
  {
    return false; // Failed to create event object
  }

  if (!(this->emptied.get_object() = CreateEvent(NULL, FALSE, TRUE, this->emptied.get_name().data())))
  {
    return false; // Failed to create event object
  }

  // Successfully created event objects.
  // We can now send signals to other processes.
  return true;
}

bool Messaging_Channel::create_mapping()
{
  // We are using INVALID_HANDLE_VALUE for handle to use a mapping object
  // backed by a system paging file so that we don't have to create a file manually

  ULONG64 size = sizeof(Message); // In bytes
  HANDLE& mapping_object = this->mapping.get_object();

  if (!(mapping_object = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size, this->mapping.get_name().data())))
  {
    return false; // Failed to create mapping object
  }

  if (!(this->mapping.get_address() = MapViewOfFile(mapping_object, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
  {
    CloseHandle(mapping_object);
    return false; // Failed to map to memory
  }

  // Successfully mapped file to memory.
  // We should now have 'shared memory' communication ready to go.
  return true;
}

// Getter to check if event and mapping stuff have been created successfully
bool Messaging_Channel::is_channel_created()
{
  return this->channel_created;
}

std::wstring& Messaging_Channel::get_id()
{
  return this->id;
}

// Create communication channel (event object and shared memory)
// This should only be called once.
// Check is_channel_created() to see if that's the case.
void Messaging_Channel::create_channel(std::wstring id)
{
  this->mapping.get_name() = id + L".mapping";
  this->sent.get_name() = id + L".event";
  this->emptied.get_name() = id + L".emptied";

  if (this->create_mapping() && this->create_event_objects())
  {
    this->channel_created = true;
    this->id = id;
  }
}

void Messaging_Channel::close()
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

  // Reset to NULL in case we wanna reuse the object with another client channel
  mapping_address = mapping_object = sent_object = emptied_object = NULL;

  // Clear the names too. Maybe unnecessary?
  this->mapping.get_name().clear();
  this->sent.get_name().clear();
  this->emptied.get_name().clear();
}

// Constructor. ID must be unique
Messaging_Channel::Messaging_Channel(std::wstring id)
{
  this->create_channel(id);
}

// Getters
Message_Event& Message_Receiver::get_sent_event()
{
  return this->sent;
}

Message_Event& Message_Receiver::get_emptied_event()
{
  return this->emptied;
}

Message_Mapping& Message_Receiver::get_mapping()
{
  return this->mapping;
}

void Message_Receiver::open(std::wstring id)
{
  this->create_channel(id);
}

// Constructor. ID must be unique
Message_Receiver::Message_Receiver(std::wstring id)
{
  this->open(id);
}

// Pulls out data from the to-be-sent queue to finally send the message to the user specified receiver.
// This function runs on its own thread.
void Message_Client::sender_loop()
{
  while (this->is_sender_thread_running)
  {
    auto queued = this->send_queue.dequeue();
    auto& receiver = queued.receiver;

    // 10 Second timeout to eventually skip sending to an uncleared channel.
    // That way we can still continue sending messages to other receivers.
    constexpr int timeout = 1000 * 10;

    // Make sure any pre-existing message has been processed
    WaitForSingleObject(receiver.get_emptied_event().get_object(), timeout);

    // Fill shared memory with next enqueued item
    *reinterpret_cast<Message*>(receiver.get_mapping().get_address()) = queued.message;

    // Signal the other process that data is ready
    SetEvent(receiver.get_sent_event().get_object());
  }
}

// Main message loop for this client.
// This function waits for messages from other processes, dereferences them
// and relays them to the user-specified message handler.
void Message_Client::receiver_loop()
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
      // message handler (user specified) for further processing
      this->handler(message);

      // Signal the other process that the message has been read.
      SetEvent(this->emptied.get_object());
    }
  }
}

void Message_Client::start_sender_loop()
{
  // Only spawn new thread if not already running
  if (!this->is_sender_thread_running)
  {
    this->is_sender_thread_running = true;
    this->sender_thread = std::thread(&Message_Client::sender_loop, this);
  }
}

void Message_Client::start_receiver_loop()
{
  // Only spawn new thread if not already running
  if (!this->is_receiver_thread_running)
  {
    this->is_receiver_thread_running = true;
    this->receiver_thread = std::thread(&Message_Client::receiver_loop, this);
  }
}

// Use this in combination with is_channel_created() to (for example)
// check if the current client object can be reassigned to a new channel
bool Message_Client::is_thread_running()
{
  return (this->is_sender_thread_running && this->is_receiver_thread_running);
}

// This function adds data to our to-be-sent queue
void Message_Client::send(Message_Receiver receiver, Message data)
{
  this->send_queue.enqueue({receiver, data});
}

// Function for assigning a user-specified message handler.
// Automatically starts message thread if it doesn't exist already.
void Message_Client::set_handler(std::function<void(Message)> handler)
{
  this->handler = handler;
  this->start_receiver_loop();
}

void Message_Client::create(std::wstring id, std::function<void(Message)> handler)
{
  this->create_channel(id);
  this->start_sender_loop();

  if (handler != nullptr)
  {
    this->set_handler(handler);
  }
}

// Close channel (for example) before reassigning to a new channel
void Message_Client::close()
{
  // Wait until all messages in the message queue are sent
  while (!this->send_queue.is_empty())
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

// Constructor. ID must be unique
Message_Client::Message_Client(std::wstring id, std::function<void(Message)> handler)
{
  this->create(id, handler);
}

Message_Client::~Message_Client()
{
  this->close();
}