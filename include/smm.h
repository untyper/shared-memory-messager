// Copyright (c) [2024] [Jovan J. E. Odassius]
//
// License: MIT (See the LICENSE file in the root directory)
// Github: https://github.com/untyper/shared-memory-messager

#ifndef SMM_SHARED_MEMORY_MESSAGER_H
#define SMM_SHARED_MEMORY_MESSAGER_H

// C/C++ includes
#include <string>
#include <functional>
#include <thread>
#include <future>
#include <atomic>
#include <memory>
#include <optional>
#include <array>
#include <utility>
#include <cstddef>
//#include <iostream>

#ifdef _WIN32
// Windows includes
#include <windows.h>
#include <mmsystem.h>
//#include <winapifamily.h>

// Remember to link against Winmm.lib in the project settings or
// alternatively uncomment the below if using Visual Studio
//#pragma comment(lib, "Winmm.lib")
#else
// Unix includes
#include <fcntl.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <unistd.h>
#include <cstring>
#include <time.h>

// Define INFINITE for Unix
#ifndef INFINITE
#define INFINITE ((unsigned int)-1)
#endif
#endif

// NOTES:
// - To use this in a UWP app, define SMM_WIN_UWP

// TODO:
// - Keep alive mechanism to remove abruptly disconnected clients
// - Increase timer delay precision and add an interval parameter to client::send

// DEV NOTES FOR FUTURE MAINTENANCE:
// - Use SMM_WIN_<NNN> format for Windows specific macro definitions.
// - Use SMM_UNIX_<NNN> format for Unix specific macro definitions.
// - Inline member fields in a class/struct should use uniform initialization.

#define SMM_MESSAGE_SIZE 4096
#define SMM_MAX_QUEUE_CAPACITY 128
#define SMM_MAX_CLIENTS_PER_SERVER 64

#define SMM_MESSAGE_ID static constexpr int _smm_id

// Negative message ID's are reserved for internal messages.
// End-users should use positive integers
#define SMM_MESSAGE_ID_CONNECTION -1
#define SMM_MESSAGE_ID_CONNECTION_RESPONSE -2
#define SMM_MESSAGE_ID_DISCONNECTION -3

// Generic client ids
#define SMM_SENDER_ID_UNKNOWN -1

// Disconnection reason codes
#define SMM_DISCONNECTION_NORMAL -1
#define SMM_DISCONNECTION_CLOSING -2

// Sandbox path attached as a prefix to mapping and semaphore string identifiers.
// For a custom path, define this before including smm.h
#ifndef SMM_SANDBOX_PATH
#define SMM_SANDBOX_PATH "SMM/SANDBOX/"
#endif

namespace smm
{
  namespace _detail
  {
    // Source: github.com/untyper/high-precision-timer
    // Cross platform high precision timer (Windows / Unix)
    class High_Precision_Timer
    {
#ifdef _WIN32
      HANDLE timer_event{ nullptr }; // Event handle for synchronization

      // Static callback for multimedia timer
      static void CALLBACK timer_proc(UINT u_timer_id, UINT u_msg, DWORD_PTR dw_user, DWORD_PTR dw1, DWORD_PTR dw2);
#endif

    public:
      // High-resolution sleep function without busy-waiting
#ifdef _WIN32
      void sleep(UINT milliseconds);
#else
      void sleep(long milliseconds);
#endif

#ifdef _WIN32
      High_Precision_Timer();
      ~High_Precision_Timer();
#endif
    };

    // Source: github.com/untyper/semaphores-and-shared-memory-classes
    // Simple cross platform Semaphore class for Unix and Windows
    class Semaphore
    {
      std::string name;

#ifdef _WIN32
      HANDLE object{ nullptr };
#else
      sem_t* object{ nullptr };
#endif

    public:
      // Getters
      const std::string& get_name() const;

#ifdef _WIN32
      HANDLE get_object() const;
#else
      sem_t* get_object() const;
#endif

      void close();
      bool wait(unsigned int timeout_ms) const;
      bool increment() const;
      bool create(const std::string& name, int initial_count = 0);

      // Constructor
      Semaphore(const std::string& name, int initial_count = 0);

      // Ask compiler to generate these for us
      Semaphore(const Semaphore&) = default;            // Copy constructor
      Semaphore& operator=(const Semaphore&) = default; // Copy assignment
      Semaphore(Semaphore&&) = default;                 // Move constructor
      Semaphore& operator=(Semaphore&&) = default;      // Move assignment

      Semaphore() {} // Default constructor
      ~Semaphore();
    };

    // Source: github.com/untyper/semaphores-and-shared-memory-classes
    // Simple cross platform Shared_Memory class for Unix and Windows
    class Shared_Memory
    {
      std::string name;
      std::size_t size{ 0 };
      void* address{ nullptr };

#ifdef _WIN32
      HANDLE file_mapping{ nullptr };
#else
      int file_mapping{ -1 };
#endif

      void* map();

    public:
      // Getters
      const std::string& get_name() const;
      std::size_t get_size() const;
      void* get_address() const;
#ifdef _WIN32
      HANDLE get_file_mapping() const;
#else
      int get_file_mapping() const;
#endif


      void close();
      bool create(const std::string& name, std::size_t size);

      // Constructor
      Shared_Memory(const std::string& name, std::size_t size);

      // Ask compiler to generate these for us
      Shared_Memory(const Shared_Memory&) = default;            // Copy constructor
      Shared_Memory& operator=(const Shared_Memory&) = default; // Copy assignment
      Shared_Memory(Shared_Memory&&) = default;                 // Move constructor
      Shared_Memory& operator=(Shared_Memory&&) = default;      // Move assignment

      Shared_Memory() {} // Default constructor
      ~Shared_Memory();
    };

    // Source: github.com/untyper/thread-safe-array
    template <typename T, std::size_t Capacity>
    class Safe_Array
    {
    private:
      struct Entry
      {
        std::shared_ptr<T> value{ nullptr };
        std::atomic<std::size_t> next_free_index{ 0 };
      };

      std::array<Entry, Capacity> data;
      std::atomic<uint64_t> free_list_head; // Stores index and counter
      static constexpr std::size_t INVALID_INDEX{ Capacity };

      // Helper functions to pack and unpack index and counter
      uint64_t pack_index_counter(std::size_t index, std::size_t counter) const
      {
        return (static_cast<uint64_t>(counter) << 32) | index;
      }

      void unpack_index_counter(uint64_t value, std::size_t& index, std::size_t& counter) const
      {
        index = static_cast<std::size_t>(value & 0xFFFFFFFF);
        counter = static_cast<std::size_t>(value >> 32);
      }

      // Push an index onto the free list
      void push_free_index(std::size_t index)
      {
        uint64_t old_head_value = this->free_list_head.load(std::memory_order_relaxed);
        uint64_t new_head_value;
        std::size_t old_head_index, old_head_counter;

        do
        {
          unpack_index_counter(old_head_value, old_head_index, old_head_counter);

          // Set the next_free_index in the Entry to the old head index
          this->data[index].next_free_index.store(old_head_index, std::memory_order_relaxed);

          // Prepare new head value with the new index and incremented counter
          std::size_t new_counter = old_head_counter + 1;
          new_head_value = pack_index_counter(index, new_counter);
        } while (!this->free_list_head.compare_exchange_weak(
          old_head_value, new_head_value, std::memory_order_release, std::memory_order_relaxed));
      }

      // Pop an index from the free list
      bool pop_free_index(std::size_t& index)
      {
        uint64_t old_head_value = this->free_list_head.load(std::memory_order_relaxed);
        uint64_t new_head_value;
        std::size_t old_head_index, old_head_counter;

        do
        {
          unpack_index_counter(old_head_value, old_head_index, old_head_counter);

          if (old_head_index == INVALID_INDEX)
          {
            return false; // Free list is empty
          }

          index = old_head_index;

          // Load the next index from the Entry
          std::size_t next_index = this->data[index].next_free_index.load(std::memory_order_relaxed);

          // Prepare new head value with next_index and incremented counter
          std::size_t new_counter = old_head_counter + 1;
          new_head_value = pack_index_counter(next_index, new_counter);

          if (this->free_list_head.compare_exchange_weak(
            old_head_value, new_head_value, std::memory_order_acquire, std::memory_order_relaxed))
          {
            return true;
          }
        } while (true);
      }

      bool erase_unchecked(std::size_t index, std::shared_ptr<T>& expected)
      {
        while (expected)
        {
          if (std::atomic_compare_exchange_weak(
            &this->data[index].value,
            &expected,
            std::shared_ptr<T>(nullptr)))
          {
            // The shared_ptr destructor will handle deletion when no references remain
            this->push_free_index(index);
            return true; // Successfully erased
          }
          // If compare_exchange_weak fails, value_container is updated to the current value
        }

        return false; // Element was already null or erased by another thread
      }

    public:
      struct Op_Result
      {
        std::size_t index{ 0 };
        T& value;
      };

      // Add an element to the array using perfect forwarding
      template<typename... Args>
      std::optional<Op_Result> insert(Args&&... args)
      {
        std::size_t index;

        if (!this->pop_free_index(index))
        {
          return std::nullopt; // Array is full
        }

        // Create a shared_ptr<T> by perfectly forwarding the arguments
        std::shared_ptr<T> new_value = std::make_shared<T>(std::forward<Args>(args)...);

        // Try to set the value atomically
        std::shared_ptr<T> expected = nullptr;

        if (!std::atomic_compare_exchange_strong(
          &this->data[index].value,
          &expected,
          new_value))
        {
          // Failed to set the value; someone else may have set it
          // Do not push the index back into the free list, as it is now in use
          return std::nullopt;
        }

        return Op_Result{ index, *new_value };
      }

      // Find an element based on a predicate, returning its index
      template <typename Predicate>
      std::optional<Op_Result> find_if(Predicate predicate) const
      {
        for (std::size_t i = 0; i < Capacity; ++i)
        {
          std::shared_ptr<T> element = std::atomic_load(&this->data[i].value);

          if (element && predicate(*element))
          {
            return Op_Result{ i, *element };
          }
        }

        return std::nullopt; // Element not found
      }

      // Find an element directly by value, returning its index
      std::optional<Op_Result> find(const T& value) const
      {
        return this->find_if([&value](const T& element) { return element == value; });
      }

      // Remove an element based on its index
      bool erase(std::size_t index)
      {
        if (index >= Capacity)
        {
          return false; // Invalid index
        }

        std::shared_ptr<T> expected = std::atomic_load(&this->data[index].value);
        return this->erase_unchecked(index, expected);
      }

      // Overload of erase to remove an element by reference
      bool erase(const T& value)
      {
        for (std::size_t i = 0; i < Capacity; ++i)
        {
          // Load the current shared_ptr atomically
          std::shared_ptr<T> current = std::atomic_load(&this->data[i].value);

          // Check if the reference matches the current element
          if (current && *current == value)
          {
            // Call the existing erase method using the index
            return this->erase_unchecked(i, current);
          }
        }

        return false; // Element not found
      }

      // Retrieve an element at the given index
      std::optional<Op_Result> at(std::size_t index) const
      {
        if (index >= Capacity)
        {
          return std::nullopt; // Invalid index
        }

        std::shared_ptr<T> element = std::atomic_load(&this->data[index].value);

        if (element)
        {
          return Op_Result{ index, *element }; // Return a copy of T
        }

        return std::nullopt; // Element is null
      }

      // Get the current size of the array
      std::size_t size() const
      {
        std::size_t count = 0;

        for (std::size_t i = 0; i < Capacity; ++i)
        {
          if (std::atomic_load(&this->data[i].value))
          {
            ++count;
          }
        }

        return count;
      }

      std::size_t capacity() const
      {
        return Capacity;
      }

      Safe_Array()
      {
        // Initialize the free list
        for (std::size_t i = 0; i < Capacity - 1; ++i)
        {
          this->data[i].next_free_index.store(i + 1, std::memory_order_relaxed);
        }

        this->data[Capacity - 1].next_free_index.store(INVALID_INDEX, std::memory_order_relaxed);

        // Initialize free_list_head with the initial index and counter 0
        this->free_list_head.store(pack_index_counter(0, 0), std::memory_order_relaxed);
      }
    };

    // Source: github.com/untyper/mpmc-shared-queue
    template <typename T>
    class Shared_Queue
    {
    private:
      struct alignas(64) Buffer_Slot
      {
        T data;
        std::atomic<bool> is_important;
        Buffer_Slot() : is_important(false) {}
      };

      struct Shared_Control_Block
      {
        std::atomic<std::size_t> head; // Consumer position
        std::atomic<std::size_t> tail; // Producer position
        std::size_t capacity{ 0 };     // Capacity of the buffer
      };

      Shared_Control_Block* control_block{ nullptr }; // Shared control block
      Buffer_Slot* buffer{ nullptr };                 // Circular buffer slots

      std::size_t wrap(std::size_t index) const
      {
        return index % this->control_block->capacity;
      }

    public:
      static constexpr std::size_t get_control_block_size()
      {
        return sizeof(Shared_Control_Block);
      }

      // Check if the buffer is empty
      bool is_empty() const
      {
        return this->control_block->head.load(std::memory_order_acquire) == this->control_block->tail.load(std::memory_order_acquire);
      }

      // Approximate size of the buffer
      std::size_t size_approx() const
      {
        std::size_t current_head = this->control_block->head.load(std::memory_order_acquire);
        std::size_t current_tail = this->control_block->tail.load(std::memory_order_acquire);
        return (current_tail >= current_head) ? (current_tail - current_head)
          : (this->control_block->capacity - (current_head - current_tail));
      }

      // Enqueue a new item
      bool enqueue(const T& item, bool important = false)
      {
        std::size_t pos = this->control_block->tail.load(std::memory_order_relaxed);
        std::size_t next_pos = wrap(pos + 1);

        if (next_pos == this->control_block->head.load(std::memory_order_acquire))
        {
          // Queue is full; search for a non-important slot to overwrite
          std::size_t search_pos = this->control_block->head.load(std::memory_order_relaxed);
          bool found_non_important = false;

          for (std::size_t i = 0; i < this->control_block->capacity; ++i)
          {
            Buffer_Slot& candidate_slot = this->buffer[wrap(search_pos)];

            if (!candidate_slot.is_important.load(std::memory_order_acquire))
            {
              found_non_important = true;
              break;
            }

            search_pos = wrap(search_pos + 1);
          }

          if (found_non_important)
          {
            // Move head to free up the non-important slot
            this->control_block->head.store(wrap(this->control_block->head.load(std::memory_order_relaxed) + 1), std::memory_order_release);
          }
          else
          {
            // No non-important slots found; overwrite the oldest important slot
            this->control_block->head.store(wrap(this->control_block->head.load(std::memory_order_relaxed) + 1), std::memory_order_release);
          }
        }

        // Write data to the current tail
        this->buffer[wrap(pos)].data = item;
        this->buffer[wrap(pos)].is_important.store(important, std::memory_order_release);
        this->control_block->tail.store(next_pos, std::memory_order_release);

        return true;
      }

      // Dequeue an item
      bool dequeue(T* item, bool* important)
      {
        std::size_t pos = this->control_block->head.load(std::memory_order_relaxed);

        if (pos == this->control_block->tail.load(std::memory_order_acquire))
        {
          // Queue is empty
          return false;
        }

        *item = this->buffer[wrap(pos)].data;
        *important = this->buffer[wrap(pos)].is_important.load(std::memory_order_relaxed);
        this->control_block->head.store(wrap(pos + 1), std::memory_order_release);

        return true;
      }

      bool create(void* shared_memory, std::size_t shared_memory_size, std::size_t requested_capacity = 0)
      {
        std::size_t alignment = alignof(std::max_align_t);
        std::size_t aligned_control_size = (sizeof(Shared_Control_Block) + alignment - 1) & ~(alignment - 1);

        if (shared_memory_size < aligned_control_size)
        {
          //throw std::runtime_error("Insufficient shared memory size for control block.");
          return false;
        }

        std::size_t buffer_space = shared_memory_size - aligned_control_size;
        std::size_t capacity = requested_capacity ? requested_capacity : (buffer_space / sizeof(Buffer_Slot));

        if (capacity == 0)
        {
          //throw std::runtime_error("Insufficient shared memory size for buffer slots.");
          return false;
        }

        this->control_block = static_cast<Shared_Control_Block*>(shared_memory);
        this->buffer = reinterpret_cast<Buffer_Slot*>(static_cast<char*>(shared_memory) + aligned_control_size);

        if (this->control_block->capacity != capacity)
        {
          // Initialize control block and buffer
          new (this->control_block) Shared_Control_Block();
          this->control_block->head.store(0, std::memory_order_relaxed);
          this->control_block->tail.store(0, std::memory_order_relaxed);
          this->control_block->capacity = capacity;

          for (std::size_t i = 0; i < capacity; ++i)
          {
            new (&this->buffer[i]) Buffer_Slot();
            this->buffer[i].is_important.store(false, std::memory_order_relaxed);
          }
        }

        return true;
      }

      explicit Shared_Queue(void* shared_memory, std::size_t shared_memory_size, std::size_t requested_capacity = 0)
      {
        this->create(shared_memory, shared_memory_size, requested_capacity);
      }

      // Default constructor
      Shared_Queue() {}
    };
  } // namespace _detail

#ifdef SMM_WIN_UWP
  // Helper to convert std::string to std::string for UWP specifics
  std::wstring string_to_wstring(const std::string& utf8_string);
#endif

  // Conversion class for all messages.
  // Use this to discern id of message before
  // casting the content buffer to the correct id for reading...
  struct Message
  {
    int id{ 0 }; // 4 bytes
    char content[SMM_MESSAGE_SIZE - sizeof(id)] = { 0 };
    // Total content size should be equal to
    // a standard page size i.e. ~4096 bytes

    int get_id() const;

    template <typename T>
    T get_content_as();

    template <typename T>
    void set_content_as(int id, T content);

    // Constructors
    template <typename T>
    Message(int id, T content);
    Message() {}
  };

  namespace _detail
  {
    struct Message_Connection
    {
      SMM_MESSAGE_ID{ SMM_MESSAGE_ID_CONNECTION };
      int sender_id{ SMM_SENDER_ID_UNKNOWN };

      Message_Connection(int sender_id) :
        sender_id(sender_id)
      {
      }

      friend struct Message;
    };

    struct Message_Connection_Response
    {
      SMM_MESSAGE_ID{ SMM_MESSAGE_ID_CONNECTION_RESPONSE };
      bool success{ false };

      Message_Connection_Response(bool success) :
        success(success)
      {
      }
    };

    struct Message_Disconnection
    {
      SMM_MESSAGE_ID{ SMM_MESSAGE_ID_DISCONNECTION };
      int sender_id{ SMM_SENDER_ID_UNKNOWN };
      int reason{ SMM_DISCONNECTION_NORMAL };

      Message_Disconnection(int sender_id, int reason = SMM_DISCONNECTION_NORMAL) :
        sender_id(sender_id),
        reason(reason)
      {
      }

      friend struct Message;
    };

    // Container for message and it's metadata
    struct Message_Packet
    {
      int sender_id{ 0 };
      Message message;
    };

    // Forward declarations internal implementation
    class _Channel;
    class _Client;
    class _Server;
  } // namespace _detail

  // Forward declarations user-interface
  class Client;
  class Server;
  class Connection;

#ifdef _WIN32
  using listening_interval_t = UINT;
#else
  using listening_interval_t = long;
#endif

  using connection_handler_t = std::function<void(Connection&)>;
  using disconnection_handler_t = std::function<void(Client&, int)>;
  using message_handler_t = std::function<void(Client&, Message&)>;

  class Client
  {
  protected:
    std::shared_ptr<_detail::_Client> shared{ nullptr };

  public:
    int get_id() const;
    bool is_connected() const;
    void disconnect(int reason = SMM_DISCONNECTION_NORMAL);

    void send(Message* message);
    void send(Message message);

    template <typename T, typename... Args>
    void send(Args... args);

    // TODO: Move assignment operator
    // TODO: Move constructor

    Client(const std::shared_ptr<_detail::_Client>& shared);
    Client& operator=(const Client& other);
    Client(const Client& other);
    Client() {}

    //friend class Safe_Array;
    friend class Server;
    friend class _detail::_Channel;
    friend class _detail::_Client;
    friend class _detail::_Server;
  };

  class Server
  {
  protected:
    std::shared_ptr<_detail::_Server> shared{ nullptr };

  public:
    bool is_thread_running();
    bool is_open();
    std::vector<Client> get_clients();
    const message_handler_t& get_handler();

    bool listen(message_handler_t message_handler = nullptr, listening_interval_t interval = 1);
    std::future<bool>& listen_async(message_handler_t message_handler = nullptr, listening_interval_t interval = 1);

    void on_connection(connection_handler_t connection_handler);
    void on_disconnection(disconnection_handler_t disconnection_handler);

    std::optional<Client> connect(int target_id);
    std::future<std::optional<Client>> connect_async(int target_id);

    void close();
    std::future<void> close_async();

    bool create(int id, message_handler_t message_handler = nullptr);

    Server(int id, message_handler_t message_handler = nullptr);
    Server() {}

    friend class Client;
    friend class _detail::_Channel;
    friend class _detail::_Client;
    friend class _detail::_Server;
  };

  // For handling connections manually
  class Connection
  {
  protected:
    bool handled{ false };
    int id{ 0 };
    _detail::_Server* server{ nullptr };

  public:
    int get_id() const;

    std::optional<Client> accept();
    void reject();

    Connection(int id, _detail::_Server* server) :
      id(id),
      server(server)
    {
    }

    Connection() {};

    friend class _detail::_Server;
  };

  namespace _detail
  {
    class _Channel
    {
    protected:
      Semaphore received_signal;
      Shared_Memory shared_memory;
      Shared_Queue<Message_Packet> message_queue;

      // True if CreateEventObject() and CreateMapping() both succeed, false otherwise
      bool channel_created{ false };
      int id{ -1 };

      bool create_channel(int id);

    public:
      bool is_channel_created() const;
      int get_id() const;
      void close();

      _Channel() {}
      _Channel(int id);

      friend class Client;
      friend class Server;
      friend class _Client;
      friend class _Server;
    };

    class _Client : public _Channel
    {
    protected:
      std::atomic<bool> connected{ false };
      _Server* server = { nullptr };

      bool open(int id);
      void close();

    public:
      int get_id() const;
      bool is_connected() const;
      void disconnect(int reason = SMM_DISCONNECTION_NORMAL);

      void send(Message* message);

      template <typename T, typename... Args>
      void send(Args&&... args);

      _Client(int id, _Server* server);
      _Client() {}
      ~_Client();

      friend class Client;
      friend class Server;
      friend class _Channel;
      friend class _Server;
    };

    class _Server : public _Channel
    {
    protected:
      std::future<bool> listening_thread;

      std::atomic<bool> listening_async{ false };
      std::atomic<bool> listening_loop_running{ false };
      std::atomic<bool> open{ false };

      Safe_Array<Client, SMM_MAX_CLIENTS_PER_SERVER> clients;

      connection_handler_t connection_handler;
      disconnection_handler_t disconnection_handler;
      message_handler_t message_handler;

      void _message_handler(int sender_id, Message& message);
      void listening_loop(listening_interval_t interval);

    public:
      bool is_thread_running();
      bool is_open();
      const message_handler_t& get_handler();

      bool listen(message_handler_t message_handler, listening_interval_t interval = 1);
      std::future<bool>& listen_async(message_handler_t message_handler = nullptr, listening_interval_t interval = 1);

      void on_connection(connection_handler_t& connection_handler);
      void on_disconnection(disconnection_handler_t& disconnection_handler);

      std::optional<Client> connect(int target_id);
      std::future<std::optional<Client>> connect_async(int target_id);

      void close();
      std::future<void> close_async();

      bool create(int id, message_handler_t message_handler = nullptr);

      _Server& operator=(const _Server&) = delete;
      _Server& operator=(_Server&& other) noexcept;
      _Server(const _Server&) = delete;
      _Server(_Server&& other) noexcept;
      _Server() {};
      ~_Server();

      _Server(int id, message_handler_t message_handler = nullptr);

      friend class Client;
      friend class Server;
      friend class Connection;

      friend class _Channel;
      friend class _Client;
    };
  } // namespace _detail

  // ********** Definitions **********

#ifdef SMM_WIN_UWP
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

  namespace _detail
  {
#ifdef _WIN32
    void CALLBACK High_Precision_Timer::timer_proc(UINT u_timer_id, UINT u_msg, DWORD_PTR dw_user, DWORD_PTR dw1, DWORD_PTR dw2)
    {
      // Access the event handle through the instance pointer
      High_Precision_Timer* instance = reinterpret_cast<High_Precision_Timer*>(dw_user);
      SetEvent(instance->timer_event); // Signal the event to unblock nano_sleep
    }

    // High-resolution sleep function without busy-waiting
    inline void High_Precision_Timer::sleep(UINT milliseconds)
    {
      if (!this->timer_event)
      {
        return;
      }

      // Reset the event
      ResetEvent(this->timer_event);

      // Start a one-shot timer with the specified delay
      MMRESULT timer_id = timeSetEvent(
        milliseconds, 1, timer_proc, reinterpret_cast<DWORD_PTR>(this), TIME_ONESHOT
      );

      if (timer_id == 0)
      {
        return;
      }

      // Wait for the timer event to be signaled
      WaitForSingleObject(this->timer_event, INFINITE);

      // Clean up the timer
      timeKillEvent(timer_id);
    }

#else // Unix
    inline void High_Precision_Timer::sleep(long milliseconds)
    {
      struct timespec req, rem;
      req.tv_sec = milliseconds / 1000;                // Convert milliseconds to seconds
      req.tv_nsec = (milliseconds % 1000) * 1'000'000; // Convert remaining milliseconds to nanoseconds
      nanosleep(&req, &rem);
    }
#endif

#ifdef _WIN32
    inline High_Precision_Timer::High_Precision_Timer()
    {
      // Set timer resolution to 1 ms for high accuracy
      timeBeginPeriod(1);

      // Create an event for synchronization
      this->timer_event = CreateEvent(NULL, FALSE, FALSE, NULL); // Auto-reset event

      if (!this->timer_event)
      {
      }
    }

    inline High_Precision_Timer::~High_Precision_Timer()
    {
      // Close the event handle and restore the timer resolution
      if (this->timer_event)
      {
        CloseHandle(this->timer_event);
      }

      timeEndPeriod(1);
    }
#endif

    // Semaphore

    inline const std::string& Semaphore::get_name() const
    {
      return this->name;
    }

#ifdef _WIN32
    HANDLE Semaphore::get_object() const
#else
    sem_t* Semaphore::get_object() const
#endif
    {
      return this->object;
    }

    inline void Semaphore::close()
    {
      if (this->object == nullptr)
      {
        return;
      }

#ifdef _WIN32
      CloseHandle(this->object);
#else
      sem_close(this->object);

      if (!this->name.empty())
      {
        sem_unlink(this->name.data());
      }
#endif

      // Clear members
      this->object = nullptr;
      this->name.clear();
    }

    inline bool Semaphore::wait(unsigned int timeout_ms) const
    {
      if (this->object == nullptr)
      {
        return false;
      }

#ifdef _WIN32
      DWORD result = WaitForSingleObject(this->object, timeout_ms);
      return result == WAIT_OBJECT_0;
#else
      if (timeout_ms == INFINITE)
      {
        return sem_wait(this->object) == 0;
      }
      else
      {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000;

        if (ts.tv_nsec >= 1000000000)
        {
          ts.tv_sec += 1;
          ts.tv_nsec -= 1000000000;
        }

        return sem_timedwait(this->object, &ts) == 0;
      }
#endif
    }

    inline bool Semaphore::increment() const
    {
      if (this->object == nullptr)
      {
        return false;
      }

#ifdef _WIN32
      return ReleaseSemaphore(this->object, 1, nullptr);
#else
      return sem_post(this->object) == 0;
#endif
    }

    inline bool Semaphore::create(const std::string& name, int initial_count)
    {
      if (name.empty())
      {
        return false;
      }

      this->name = name;

#ifdef _WIN32
      this->object = CreateSemaphoreA(nullptr, initial_count, LONG_MAX, name.data());
      return this->object != nullptr;
#else
      this->object = sem_open(name.data(), O_CREAT, 0666, initial_count);
      return this->object != SEM_FAILED;
#endif
    }

    inline Semaphore::Semaphore(const std::string& name, int initial_count)
    {
      this->create(name, initial_count);
    }

    inline Semaphore::~Semaphore()
    {
      this->close();
    }

    // Shared_Memory

    inline const std::string& Shared_Memory::get_name() const
    {
      return this->name;
    }

    inline std::size_t Shared_Memory::get_size() const
    {
      return this->size;
    }

    inline void* Shared_Memory::get_address() const
    {
      return this->address;
    }

#ifdef _WIN32
    inline HANDLE Shared_Memory::get_file_mapping() const
#else
    inline int Shared_Memory::get_file_mapping() const
#endif
    {
      return this->file_mapping;
    }

    inline void Shared_Memory::close()
    {
#ifdef _WIN32
      if (this->file_mapping == nullptr)
#else
      if (this->file_mapping == -1)
#endif
      {
        return;
      }

#ifdef _WIN32
      if (this->address != nullptr)
      {
        UnmapViewOfFile(this->address);
      }

      CloseHandle(this->file_mapping);
#else
      if (this->address != nullptr)
      {
        munmap(this->address, this->size);
      }

      close(this->file_mapping);

      if (!this->name.empty())
      {
        shm_unlink(this->name.data());
      }
#endif

      // Finally clear members
      this->name.clear();
      this->size = 0;
      this->address = nullptr;

#ifdef _WIN32
      this->file_mapping = nullptr;
#else
      this->file_mapping = -1;
#endif
    }

    inline void* Shared_Memory::map()
    {
      if (this->file_mapping == nullptr)
      {
        return nullptr;
      }

      if (this->size == 0)
      {
        return nullptr;
      }

#ifdef _WIN32
#ifdef SMM_WIN_UWP
      void* address = MapViewOfFileFromApp(this->file_mapping, FILE_MAP_ALL_ACCESS, 0, this->size); // Or size = 0
#else
      void* address = MapViewOfFile(this->file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, this->size); // Or size = 0
#endif

      if (address == nullptr)
      {
        CloseHandle(this->file_mapping); // Cleanup handle
        this->file_mapping = nullptr;
      }

      return address;
#else
      void* address = mmap(nullptr, this->size, PROT_READ | PROT_WRITE, MAP_SHARED, this->file_mapping, 0);

      if (address == MAP_FAILED)
      {
        close(this->file_mapping); // Cleanup file descriptor
        this->file_mapping = -1;
        return nullptr;
      }

      return address;
#endif
    }

    inline bool Shared_Memory::create(const std::string& name, std::size_t size)
    {
      if (name.empty())
      {
        return false;
      }

      if (size == 0)
      {
        return false;
      }

      this->name = name;
      this->size = size;

#ifdef _WIN32
#ifdef SMM_WIN_UWP
      this->file_mapping = CreateFileMappingFromApp(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, static_cast<DWORD>(size), string_to_wstring(name).data());
#else
      this->file_mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, static_cast<DWORD>(size), name.data());
#endif
      // return this->file_mapping != nullptr;
#else
      int shm_fd = shm_open(name.data(), O_CREAT | O_RDWR, 0666);

      if (shm_fd == -1)
      {
        return false;
      }

      if (ftruncate(shm_fd, size) == -1)
      {
        close(shm_fd);
        shm_unlink(name.data());
        return false;
      }

      this->file_mapping = shm_fd;
      // return true;
#endif

      // Now map to memory
      this->address = this->map();
      return this->address != nullptr;
    }

    inline Shared_Memory::Shared_Memory(const std::string& name, std::size_t size)
    {
      this->create(name, size);
    }

    inline Shared_Memory::~Shared_Memory()
    {
      this->close();
    }

    // _Channel, base of _Client and _Server

    // Create communication channel (event object and shared memory)
    // This should only be called once.
    // Check is_channel_created() to see if that's the case.
    inline bool _Channel::create_channel(int id)
    {
      std::string id_string = std::to_string(id);

      // Construct mapping and semaphore id strings.
      // Isolates from global namespace to sandbox.
      std::string file_mapping_name = SMM_SANDBOX_PATH + id_string + ".mapping";
      std::string semaphore_name = SMM_SANDBOX_PATH + id_string + ".signal";

      constexpr std::size_t shared_memory_size =
        Shared_Queue<Message_Packet>::get_control_block_size()
        + SMM_MESSAGE_SIZE
        * SMM_MAX_QUEUE_CAPACITY;

      if (!this->shared_memory.create(file_mapping_name, shared_memory_size))
      {
        return false;
      }

      if (!this->received_signal.create(semaphore_name))
      {
        return false;
      }

      // Create a message queue in the newly created shared memory
      this->message_queue.create(this->shared_memory.get_address(), shared_memory_size);

      // Success! We should now have 'shared memory' communication ready to go.
      this->id = id;
      return (this->channel_created = true);
    }

    // Getter to check if event and mapping stuff have been created successfully
    inline bool _Channel::is_channel_created() const
    {
      return this->channel_created;
    }

    inline int _Channel::get_id() const
    {
      return this->id;
    }

    inline void _Channel::close()
    {
      this->shared_memory.close();
      this->received_signal.close();
    }

    // Constructor. ID must be unique
    inline _Channel::_Channel(int id)
    {
      this->create_channel(id);
    }
  } // namespace _detail

  inline int Message::get_id() const
  {
    return this->id;
  }

  template <typename T>
  inline T Message::get_content_as()
  {
    return *reinterpret_cast<T*>(this->content);
  }

  template <typename T>
  inline void Message::set_content_as(int id, T content)
  {
    this->id = id;
    *reinterpret_cast<T*>(this->content) = content;
  }

  template <typename T>
  inline Message::Message(int id, T content)
  {
    this->set_content_as(id, content);
  }

  inline bool Client::is_connected() const
  {
    return this->shared->is_connected();
  }

  inline int Client::get_id() const
  {
    return this->shared->get_id();
  }

  inline void Client::disconnect(int reason)
  {
    this->shared->disconnect(reason);
  }

  inline void Client::send(Message* message)
  {
    this->shared->send(message);
  }

  inline void Client::send(Message message)
  {
    this->shared->send(&message);
  }

  template <typename T, typename... Args>
  inline void Client::send(Args... args)
  {
    this->shared->send<T>(std::forward<Args>(args)...);
  }

  // TODO: Move assignment operator
  // TODO: Move constructor

  // Copy assignment operator
  inline Client& Client::operator=(const Client& other)
  {
    // Avoid self-assignment
    if (this != &other)
    {
      this->shared = other.shared;
    }

    return *this;
  }

  // Copy constructor
  inline Client::Client(const Client& other) :
    shared(other.shared)
  {
  }

  inline Client::Client(const std::shared_ptr<_detail::_Client>& shared)
  {
    this->shared = shared;
  }

  inline bool Server::is_thread_running()
  {
    return this->shared->is_thread_running();
  }

  inline bool Server::is_open()
  {
    return this->shared->is_open();
  }

  // Converts Safe_Array to vector for idiomatic usage
  inline std::vector<Client> Server::get_clients()
  {
    std::vector<Client> clients;

    auto& safe_clients = this->shared->clients;
    std::size_t capacity = safe_clients.capacity();

    for (int i = 0; i < capacity; ++i)
    {
      auto client_exists = safe_clients.at(i);

      if (client_exists)
      {
        clients.push_back(client_exists->value);
      }
    }

    return clients;
  }

  inline const message_handler_t& Server::get_handler()
  {
    return this->shared->get_handler();
  }

  inline bool Server::listen(message_handler_t message_handler, listening_interval_t interval)
  {
    return this->shared->listen(message_handler, interval);
  }

  inline std::future<bool>& Server::listen_async(message_handler_t message_handler, listening_interval_t interval)
  {
    return this->shared->listen_async(message_handler, interval);
  }

  inline void Server::on_connection(connection_handler_t connection_handler)
  {
    this->shared->on_connection(connection_handler);
  }

  inline void Server::on_disconnection(disconnection_handler_t disconnection_handler)
  {
    this->shared->on_disconnection(disconnection_handler);
  }

  inline std::optional<Client> Server::connect(int target_id)
  {
    return this->shared->connect(target_id);
  }

  inline std::future<std::optional<Client>> Server::connect_async(int target_id)
  {
    return this->shared->connect_async(target_id);
  }

  inline void Server::close()
  {
    this->shared->close();
  }

  inline std::future<void> Server::close_async()
  {
    return this->shared->close_async();
  }

  inline bool Server::create(int id, message_handler_t message_handler)
  {
    return this->shared->create(id, message_handler);
  }

  inline Server::Server(int id, message_handler_t message_handler)
  {
    // TODO:
    //  Maybe first check a global fixed sized shared memory block to see if client with specific ID already exists?

    this->shared = std::make_shared<_detail::_Server>(id, message_handler);

    if (!this->shared->open.load())
    {
      this->shared = nullptr;
      return;
    }
  }

  int Connection::get_id() const
  {
    return this->id;
  }

  inline std::optional<Client> Connection::accept()
  {
    auto client_exists = this->server->clients.find_if([id = this->id](const Client& client)
    {
      return client.get_id() == id;
    });

    if (client_exists)
    {
      return std::nullopt; // Client already exists, skip
    }

    // Save client to clients list.
    auto& new_client = this->server->clients.insert(std::make_shared<_detail::_Client>(this->id, this->server))->value;

    // Send success response to connecting client, and signal-it to wake up connecting client's thread
    new_client.send<_detail::Message_Connection_Response>(true);

    // Mark as handled so internal handler doesn't handle it for the second time
    this->handled = true;

    return new_client;
  }

  inline void Connection::reject()
  {
    if (!this->handled)
    {
      // Mark as handled so internal handler doesn't handle it for the second time
      this->handled = true;
    }

    // Nothing else here for now
  }

  namespace _detail
  {
    inline bool _Client::open(int id)
    {
      if (this->create_channel(id))
      {
        this->connected.store(true);
        return true; // Success
      }

      return false; // Error
    }

    inline void _Client::close()
    {
      this->connected.store(false);
      this->server = nullptr;

      _Channel::close();
    }

    inline bool _Client::is_connected() const
    {
      return this->connected.load();
    }

    inline int _Client::get_id() const
    {
      return this->id;
    }

    inline void _Client::disconnect(int reason)
    {
      this->send<Message_Disconnection>(this->server->id, reason);

      auto client_exists = this->server->clients.find_if([this](const Client& client)
      {
        return client.get_id() == this->id;
      });

      if (client_exists)
      {
        this->server->clients.erase(client_exists->index);
      }

      this->connected.store(false);
    }

    inline void _Client::send(Message* message)
    {
      if (!this->connected.load())
      {
        return;
      }

      // Enqueue message in shared memory queue
      // TODO: Handle messages marked as important

      Message_Packet data;
      data.sender_id = this->server->id;
      data.message = *message;

      this->message_queue.enqueue(data);

      // Signal to connected client that they have received a message
      this->received_signal.increment();
    }

    template <typename T, typename... Args>
    inline void _Client::send(Args&&... args)
    {
      // Construct custom message
      T custom_message(std::forward<Args>(args)...);

      // NOTE:
      //  If _smm_id is protected, end-user must declare
      //  message struct as friend class of smm::Message
      int id = custom_message._smm_id;
      Message message(id, custom_message);

      this->send(&message);
    }

    // Constructor. ID must be unique
    inline _Client::_Client(int id, _Server* server) :
      server(server)
    {
      this->open(id);
    }

    inline _Client::~_Client()
    {
      this->close();
    }

    inline void _Server::_message_handler(int sender_id, Message& message)
    {
      Client sender;

      auto client_exists = this->clients.find_if([sender_id](const Client& client)
      {
        return client.get_id() == sender_id;
      });

      if (client_exists)
      {
        sender = client_exists->value;
      }

      switch (message.get_id())
      {
        case SMM_MESSAGE_ID_CONNECTION:
        {
          if (client_exists)
          {
            // Connection message from a client that already exists in our list?
            // Makes no sense, skip
            break;
          }

          Connection connection_attempt(sender_id, this);

          if (this->connection_handler)
          {
            this->connection_handler(connection_attempt);

            //if (connection_attempt.handled)
            //{
            //  break; // User has already handled the connection
            //}

            // User hasn't handled the connection, so accept it here by default?
            //connection_attempt.accept();
          }
          else
          {
            // No user-specified handler provided, accept connection by default
            connection_attempt.accept();
          }

          break;
        }

        case SMM_MESSAGE_ID_DISCONNECTION:
        {
          if (!client_exists)
          {
            // Disconnection message from a client that doesn't exist in our list?
            // Makes no sense, skip
            break;
          }

          if (this->disconnection_handler)
          {
            int reason = message.get_content_as<Message_Disconnection>().reason;
            this->disconnection_handler(sender, reason);
          }

          // Finally remove from our list
          sender.shared->connected.store(false);
          this->clients.erase(client_exists->index);
          break;
        }

        // Not an internal message, redirect to user-specified message handler
        default:
        {
          if (!client_exists)
          {
            break;
          }

          if (this->message_handler)
          {
            this->message_handler(sender, message);
          }

          break;
        }
      }
    }

    // Main message loop for this client.
    // This function waits for messages from other processes, deqeueues them from shared-memory
    // and relays them to the user-specified message handler.
    inline void _Server::listening_loop(listening_interval_t interval)
    {
      // TODO: Integrate timer into _Server as a member instead
      High_Precision_Timer timer;

      while (this->listening_loop_running.load())
      {
        // Wait for a message
        timer.sleep(interval);
        this->received_signal.wait(INFINITE);

        //Message message;
        bool important = false;
        Message_Packet data;

        // Even though we have received a signal about a received message,
        // due to the concurrent nature of this program, we check if the buffer is empty anyway...
        if (!this->message_queue.dequeue(&data, &important))
        {
          continue; // Skip if buffer empty
        }

        this->_message_handler(data.sender_id, data.message);
      }
    }

    // Use this in combination with is_channel_created() to (for example)
    // check if the current client object can be reassigned to a new channel
    inline bool _Server::is_thread_running()
    {
      return this->listening_loop_running.load();
    }

    inline bool _Server::is_open()
    {
      return this->open.load();
    }

    // This can be used to check if a handler is already set
    inline const message_handler_t& _Server::get_handler()
    {
      return this->message_handler;
    }

    // This function or it's async variant must be called before connecting or sending messages
    inline bool _Server::listen(message_handler_t message_handler, listening_interval_t interval)
    {
      if (!this->open.load())
      {
        return false;
      }

      this->listening_loop_running.store(true);
      this->message_handler = message_handler;
      this->listening_loop(interval);

      return true;
    }

    inline std::future<bool>& _Server::listen_async(message_handler_t message_handler, listening_interval_t interval)
    {
      // Promisify return value
      std::promise<bool> promise;
      this->listening_thread = promise.get_future();

      // Only spawn a new thread if not already running
      if (this->listening_loop_running.load())
      {
        promise.set_value(false);
        return this->listening_thread;
      }

      //this->listening_thread = std::thread(&_Server::listen, this, message_handler, interval);
      this->listening_thread = std::async(std::launch::async, &_Server::listen, this, message_handler, interval);
      this->listening_async.store(true);
      return this->listening_thread;
    }

    inline void _Server::on_connection(connection_handler_t& connection_handler)
    {
      this->connection_handler = connection_handler;
    }

    inline void _Server::on_disconnection(disconnection_handler_t& disconnection_handler)
    {
      this->disconnection_handler = disconnection_handler;
    }

    inline std::optional<Client> _Server::connect(int target_id)
    {
      std::optional<Client> result;

      auto client_exists = this->clients.find_if([target_id](const Client& client)
      {
        return client.get_id() == target_id;
      });

      if (client_exists)
      {
        // Return client with given id if it's already connected to us
        return client_exists->value;
      }

      // We aren't connected to the client and the server isn't connected to us,
      // so establish the connection
      Client new_client(std::make_shared<_Client>(target_id, this));

      // Send our id to new_client in connection message
      new_client.send<Message_Connection>(this->id);

      // Temporary wrapper
      struct Hostage
      {
        Message_Packet data;
        bool important = false;
      };

      std::vector<Hostage> hostages;

      while (true)
      {
        this->received_signal.wait(INFINITE); // Wait for message signal to avoid busy waiting
        Hostage hostage;

        if (!this->message_queue.dequeue(&hostage.data, &hostage.important))
        {
          break; // Queue is empty, skip
        }

        if (hostage.data.message.id != SMM_MESSAGE_ID_CONNECTION_RESPONSE)
        {
          // Not our message, keep as hostage to enqueue back later
          hostages.push_back(hostage);
          continue;
        }

        auto response = hostage.data.message.get_content_as<Message_Connection_Response>();

        if (response.success)
        {
          this->clients.insert(new_client);
          result = new_client;
        }
        else
        {
          result = std::nullopt;
        }

        break;
      }

      // Re-enqueue dequeued messages back into regular processing
      for (auto& hostage : hostages)
      {
        this->message_queue.enqueue(hostage.data, hostage.important);
      }

      // Finally return the connected-to client in order to send messages idiomatically
      return result;
    }

    inline std::future<std::optional<Client>> _Server::connect_async(int target_id)
    {
      return std::async(std::launch::async, &_Server::connect, this, target_id);
    }

    // Close channel (for example) before reassigning to a new channel
    inline void _Server::close()
    {
      // Mark as closed, to disallow more sends
      this->open.store(false);

      // Wait until all remaining messages in message_queue are processed
      // TODO: Timeout?
      while (!this->message_queue.is_empty())
      {
        // TODO: Use High_Precision_Timer instead
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); // Sleep to avoid busy waiting
      }

      // Signal to message threads to terminate
      this->listening_loop_running.store(false);

      // Join threads with main thread
      if (this->listening_async.load())
      {
        this->listening_thread.get();
      }

      // Disconnect all clients in clients
      // When thats done, there will no longer be open handles to the shared memory, and thus the OS will free it
      for (std::size_t i = 0; i < this->clients.size(); ++i)
      {
        auto client_exists = this->clients.at(i);

        if (!client_exists)
        {
          continue;
        }

        client_exists->value.disconnect(SMM_DISCONNECTION_CLOSING);
      }

      // Unmap file memory and close all handles
      _Channel::close();
    }

    inline std::future<void> _Server::close_async()
    {
      return std::async(std::launch::async, &_Server::close, this);
    }

    inline bool _Server::create(int id, message_handler_t message_handler)
    {
      // Only closed client instances can create a channel.
      if (this->open.load())
      {
        return false;
      }

      if (!this->create_channel(id))
      {
        return false;
      }

      if (message_handler != nullptr)
      {
        // TODO: Error checking
        this->listen_async(message_handler);
      }

      this->open.store(true);
      return true; // Success!
    }

    // Move assignment operator
    inline _Server& _Server::operator=(_Server&& other) noexcept
    {
      // Avoid self-assignment
      if (this != &other)
      {
        _Channel::operator=(std::move(other));
        this->listening_thread = std::move(other.listening_thread);
        this->message_handler = std::move(other.message_handler);

        this->listening_async.store(other.listening_async.load());
        this->listening_loop_running.store(other.listening_loop_running.load());

        // Reset other to indicate moved-from state
        other.listening_async.store(false);
        other.listening_loop_running.store(false);
      }

      return *this;
    }

    // Move constructor
    inline _Server::_Server(_Server&& other) noexcept :
      _Channel(std::move(other)),
      listening_thread(std::move(other.listening_thread)),
      message_handler(std::move(other.message_handler))
    {
      this->listening_async.store(other.listening_async.load());
      this->listening_loop_running.store(other.listening_loop_running.load());

      // Reset other to indicate moved-from state
      other.listening_async.store(false);
      other.listening_loop_running.store(false);
    }

    // Constructor. ID must be unique
    inline _Server::_Server(int id, message_handler_t message_handler)
    {
      this->create(id, message_handler);
    }

    inline _Server::~_Server()
    {
      this->close();
    }
  } // namespace _detail

} // namespace smm

#endif // SMM_SHARED_MEMORY_MESSAGER_H
