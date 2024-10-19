#pragma once

#include <string>
#include <functional>
#include <utility>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

#include <Windows.h>

// NOTE:
// Each MessageClient only has one message 'slot'.
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

// Ref: stackoverflow.com/a/16075550
// A threadsafe-queue.
template <class T>
class MessageQueue
{
  private:
  std::queue<T> queue;
  mutable std::mutex mutex;
  std::condition_variable condition;

  public:
  // Add an element to the queue.
  void Enqueue(T t)
  {
    std::lock_guard<std::mutex> lock(this->mutex);
    this->queue.push(t);
    this->condition.notify_one();
  }

  // Get the "front"-element.
  // If the queue is empty, wait till an element is available.
  T Dequeue()
  {
    std::unique_lock<std::mutex> lock(this->mutex);
    this->condition.wait(lock, [&] { return !queue.empty(); });

    T value = this->queue.front();
    this->queue.pop();
    return value;
  }

  // Clear the queue.
  void Clear()
  {
    std::lock_guard<std::mutex> lock(this->mutex);
    this->queue = {};
    this->condition.notify_one();
  }

  bool IsEmpty()
  {
    std::lock_guard<std::mutex> lock(this->mutex);
    bool empty = this->queue.empty();
    this->condition.notify_one();
    return empty;
  }

  MessageQueue() : queue(), mutex(), condition() {}
  ~MessageQueue() {}
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

  UINT GetType()
  {
    return this->type;
  }

  template <typename ContentType>
  ContentType GetContentAs()
  {
    return *reinterpret_cast<ContentType*>(this->content);
  }

  template <typename ContentType>
  void SetContentAs(UINT type, ContentType content)
  {
    this->type = type;
    *reinterpret_cast<ContentType*>(this->content) = content;
  }

  // Templates on a constructor? :o
  template <typename ContentType>
  Message(UINT type, ContentType content)
  {
    this->SetContentAs(type, content);
  }

  Message() {}
};

class MessageObject
{
  private:
  std::wstring name;
  HANDLE object = NULL;

  public:
  std::wstring& GetName();
  HANDLE& GetObject();
};

using MessageEvent = MessageObject;

class MessageMapping : public MessageObject
{
  private:
  PVOID address = NULL; // byte to byte file mapping object's address

  public:
  PVOID& GetAddress();
};

class MessagingChannel
{
  protected:
  // True if CreateEventObject() and CreateMapping() both succeed, false otherwise
  bool isChannelCreated = false;

  MessageEvent sent;
  MessageEvent emptied;
  MessageMapping mapping;

  // Member functions below
  bool CreateEventObjects();
  bool CreateMapping();
  void CreateChannel(std::wstring id);

  public:
  bool IsChannelCreated();
  void Close();

  // Constructors
  MessagingChannel(std::wstring id);
  MessagingChannel() {}
};

class MessageReceiver : public MessagingChannel
{
  public:
  // Getters
  MessageEvent& GetSentEvent();
  MessageEvent& GetEmptiedEvent();
  MessageMapping& GetMapping();

  void Open(std::wstring id);

  MessageReceiver(std::wstring id);
  MessageReceiver() {}
};

struct MessageInfo
{
  MessageReceiver receiver;
  Message message;
};

class MessageClient : public MessagingChannel
{
  protected:
  bool isSenderThreadRunning = false;
  bool isReceiverThreadRunning = false;

  MessageQueue<MessageInfo> sendQueue;
  std::function<void(Message)> handler;

  // Member functions below
  void SenderLoop();
  void ReceiverLoop();
  void StartSenderLoop();
  void StartReceiverLoop();

  public:
  bool IsThreadRunning();
  void Send(MessageReceiver receiver, Message data);
  void SetHandler(std::function<void(Message)> handler);
  void Create(std::wstring id, std::function<void(Message)> handler = nullptr);
  void Close(); // Override

  MessageClient(std::wstring id, std::function<void(Message)> handler = nullptr);
  MessageClient() {};
};
