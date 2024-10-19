#include "Communication.h"

std::wstring& MessageObject::GetName()
{
  return this->name;
}

HANDLE& MessageObject::GetObject()
{
  return this->object;
}

PVOID& MessageMapping::GetAddress()
{
  return this->address;
}

// Member functions below
bool MessagingChannel::CreateEventObjects()
{
  if (!(this->sent.GetObject() = CreateEvent(NULL, FALSE, FALSE, this->sent.GetName().data())))
  {
    return false; // Failed to create event object
  }

  if (!(this->emptied.GetObject() = CreateEvent(NULL, FALSE, TRUE, this->emptied.GetName().data())))
  {
    return false; // Failed to create event object
  }

  // Successfully created event objects.
  // We can now send signals to other processes.
  return true;
}

bool MessagingChannel::CreateMapping()
{
  // We are using INVALID_HANDLE_VALUE for handle to use a mapping object
  // backed by a system paging file so that we don't have to create a file manually

  ULONG64 size = sizeof(Message); // In bytes
  HANDLE& mappingObject = this->mapping.GetObject();

  if (!(mappingObject = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, size, this->mapping.GetName().data())))
  {
    return false; // Failed to create mapping object
  }

  if (!(this->mapping.GetAddress() = MapViewOfFile(mappingObject, FILE_MAP_ALL_ACCESS, 0, 0, 0)))
  {
    CloseHandle(mappingObject);
    return false; // Failed to map to memory
  }

  // Successfully mapped file to memory.
  // We should now have 'shared memory' communication ready to go.
  return true;
}

// Getter to check if event and mapping stuff have been created successfully
bool MessagingChannel::IsChannelCreated()
{
  return this->isChannelCreated;
}

// Create communication channel (event object and shared memory)
// This should only be called once.
// Check IsChannelCreated() to see if that's the case.
void MessagingChannel::CreateChannel(std::wstring id)
{
  this->mapping.GetName() = id + L".mapping";
  this->sent.GetName() = id + L".event";
  this->emptied.GetName() = id + L".emptied";

  if (this->CreateMapping() && this->CreateEventObjects())
  {
    this->isChannelCreated = true;
  }
}

void MessagingChannel::Close()
{
  PVOID& mappingAddress = this->mapping.GetAddress();
  HANDLE& mappingObject = this->mapping.GetObject();
  HANDLE& sentObject = this->sent.GetObject();
  HANDLE& emptiedObject = this->emptied.GetObject();

  // TODO: Some error checking?
  // Release handles and unmap shared memory
  UnmapViewOfFile(mappingAddress);
  CloseHandle(mappingObject);
  CloseHandle(sentObject);
  CloseHandle(emptiedObject);

  // Reset to NULL in case we wanna reuse the object with another client channel
  mappingAddress = mappingObject = sentObject = emptiedObject = NULL;

  // Clear the names too. Maybe unnecessary?
  this->mapping.GetName().clear();
  this->sent.GetName().clear();
  this->emptied.GetName().clear();
}

// Constructor. ID must be unique
MessagingChannel::MessagingChannel(std::wstring id)
{
  this->CreateChannel(id);
}

// Getters
MessageEvent& MessageReceiver::GetSentEvent()
{
  return this->sent;
}

MessageEvent& MessageReceiver::GetEmptiedEvent()
{
  return this->emptied;
}

MessageMapping& MessageReceiver::GetMapping()
{
  return this->mapping;
}

void MessageReceiver::Open(std::wstring id)
{
  this->CreateChannel(id);
}

// Constructor. ID must be unique
MessageReceiver::MessageReceiver(std::wstring id)
{
  this->Open(id);
}

// Pulls out data from the to-be-sent queue to finally send the message to the user specified receiver.
// This function runs on its own thread.
void MessageClient::SenderLoop()
{
  while (this->isSenderThreadRunning)
  {
    auto queued = this->sendQueue.Dequeue();
    auto& receiver = queued.receiver;

    // TODO:
    // Change INFINITE to a 10 second timeout in case process doesn't signal the 'emptied' event to us.
    // That way we can still continue sending messages to other receivers.

    // Make sure any pre-existing message has been processed
    WaitForSingleObject(receiver.GetEmptiedEvent().GetObject(), INFINITE);

    // Fill shared memory with next enqueued item
    *reinterpret_cast<Message*>(receiver.GetMapping().GetAddress()) = queued.message;

    // Signal the other process that data is ready
    SetEvent(receiver.GetSentEvent().GetObject());
  }
}

// Main message loop for this client.
// This function waits for messages from other processes, dereferences them
// and relays them to the user-specified message handler.
void MessageClient::ReceiverLoop()
{
  while (this->isReceiverThreadRunning)
  {
    if (this->handler)
    {
      // Wait for a message
      WaitForSingleObject(this->sent.GetObject(), INFINITE);

      // Read shared memory into a message object
      auto message = *reinterpret_cast<Message*>(this->mapping.GetAddress());

      // Now pass the message object to our
      // message handler (user specified) for further processing
      this->handler(message);

      // Signal the other process that the message has been read.
      SetEvent(this->emptied.GetObject());
    }
  }
}

void MessageClient::StartSenderLoop()
{
  // Only spawn new thread if not already running
  if (!this->isSenderThreadRunning)
  {
    this->isSenderThreadRunning = true;
    std::thread(&MessageClient::SenderLoop, this).detach();
  }
}

void MessageClient::StartReceiverLoop()
{
  // Only spawn new thread if not already running
  if (!this->isReceiverThreadRunning)
  {
    this->isReceiverThreadRunning = true;
    std::thread(&MessageClient::ReceiverLoop, this).detach();
  }
}

// Use this in combination with IsChannelCreated() to (for example)
// check if the current client object can be reassigned to a new channel
bool MessageClient::IsThreadRunning()
{
  return (this->isSenderThreadRunning && this->isReceiverThreadRunning);
}

// This function adds data to our to-be-sent queue
void MessageClient::Send(MessageReceiver receiver, Message data)
{
  this->sendQueue.Enqueue({receiver, data});
}

// Function for assigning a user-specified message handler.
// Automatically starts message thread if it doesn't exist already.
void MessageClient::SetHandler(std::function<void(Message)> handler)
{
  this->handler = handler;
  this->StartReceiverLoop();
}

void MessageClient::Create(std::wstring id, std::function<void(Message)> handler)
{
  this->CreateChannel(id);
  this->StartSenderLoop();

  if (handler != nullptr)
  {
    this->SetHandler(handler);
  }
}

// Close channel (for example) before reassigning to a new channel
void MessageClient::Close()
{
  // Wait until all messages in the message queue are sent
  while (!this->sendQueue.IsEmpty())
  {
    Sleep(10);
  }

  // Unmap file memory and close all handles
  this->Close();

  // Signal to message threads to terminate
  this->isSenderThreadRunning = false;
  this->isReceiverThreadRunning = false;
}

// Constructor. ID must be unique
MessageClient::MessageClient(std::wstring id, std::function<void(Message)> handler)
{
  this->Create(id, handler);
}
