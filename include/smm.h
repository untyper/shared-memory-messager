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
#include <climits>
#include <type_traits>
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
// - To use this in a UWP app:
//   1. Define SMM_WIN_UWP before including this file
//   2. To interact with the UWP app, an external client must
//      connect through the UWP app's namespace. Retrieve it with GetAppContainerNamedObjectPath()
//      in the UWP app and pass it to the client through a fullTrustProcess (for example).

// TODO:
// - (Important)  Keep alive mechanism to remove abruptly disconnected clients
// - (Important)  Test on Unix. No tests have been conducted on Unix yet.
// - (Desired)    Error codes instead of booleans?
// - (Desired)    Wrap 'shared->' dereferences in proper checks for cohesive error messages and failure control.
// - (Desried)    Mark functions noexcept where appropriate.
// - (Maybe?)     Callbacks for async functions to execute code right after thread launch?

// DEV NOTES FOR FUTURE MAINTENANCE:
// - Use SMM_WIN_<NNN> format for Windows specific macro definitions.
// - Use SMM_UNIX_<NNN> format for Unix specific macro definitions.
// - Inline member fields in a class/struct should use uniform initialization.
// - All non-empty string literals must be encrypted with string::encrypt().
//   Dev is free to define SMM_STRING_SHIFT_AMOUNT for custom encryption outcomes.

// End-ser can define this macro to isolate their program
// from global access due to id conflicts.
// Don't uncomment this, instead define this macro before including this file
// or define it in the compiler definitions flag (/D on MSVC and -D on GCC).
//#ifndef SMM_DOMAIN
//#define SMM_DOMAIN "example.domain:app"
//#endif

// End-user customizeable macro definitions
#ifndef SMM_MESSAGE_SIZE
#define SMM_MESSAGE_SIZE 4096
#endif

#ifndef SMM_MAX_QUEUE_CAPACITY
#define SMM_MAX_QUEUE_CAPACITY 16
#endif

#ifndef SMM_MAX_CLIENTS_PER_SERVER
#define SMM_MAX_CLIENTS_PER_SERVER 64
#endif

// String shift-encryption:
// - 0  = No enctryption
// - 1+ = Encryption
#ifndef SMM_STRING_SHIFT_AMOUNT
#define SMM_STRING_SHIFT_AMOUNT 2
#endif

// Non-customizeable macro definitions
#define SMM_MESSAGE_ID static constexpr int _smm_message_id
#define SMM_SET_MESSAGE_ID(id) SMM_MESSAGE_ID = id
#define SMM_GET_MESSAGE_ID(message) message::_smm_message_id
#define SMM_REUSE_MESSAGE_ID(message) SMM_MESSAGE_ID = SMM_GET_MESSAGE_ID(message)

// Negative message ID's are reserved for internal messages.
// End-users should use positive integers
#define SMM_MESSAGE_ID_UNKNOWN -1
#define SMM_MESSAGE_ID_NO_RESPONSE -2
#define SMM_MESSAGE_ID_CONNECTION -3
#define SMM_MESSAGE_ID_CONNECTION_RESPONSE -4
#define SMM_MESSAGE_ID_DISCONNECTION -5

// Generic client ids
#define SMM_CLIENT_ID_UNKNOWN -1
#define SMM_SENDER_ID_UNKNOWN SMM_CLIENT_ID_UNKNOWN

// Disconnection reason codes
#define SMM_DISCONNECTION_NORMAL -1
#define SMM_DISCONNECTION_CLOSING -2

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
      inline static constexpr int max_count{ 1024 };

      // Getters
      const std::string& get_name() const;

#ifdef _WIN32
      HANDLE get_object() const;
#else
      sem_t* get_object() const;
#endif

      void close();
      bool wait(unsigned int timeout_ms = INFINITE) const;
      bool increment(int count = 1) const;
      bool create(const std::string& name, int initial_count = 0);

      // Constructor
      Semaphore(const std::string& name, int initial_count = 0);

      // Ask compiler to generate these for us
      Semaphore(const Semaphore&) = default;            // Copy constructor
      Semaphore& operator=(const Semaphore&) = default; // Copy assignment
      Semaphore(Semaphore&&) = default;                 // Move constructor
      Semaphore& operator=(Semaphore&&) = default;      // Move assignment

      Semaphore() = default;
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

      Shared_Memory() = default;
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
      Shared_Queue() = default;
    };

    // Basic string encryption logic
    namespace string
    {
      // Compile-time shift-based encryption structure
      template <size_t N>
      struct Encrypted_String {
        char data[N];

        constexpr const char* get() const {
          return data; // Return encrypted data
        }
      };

      // Function to shift a character forward within alphanumeric ranges
      constexpr char shift_char_forward(char c, int shift_amount)
      {
        if (c >= 'A' && c <= 'Z')
        {
          // Shift within uppercase letters
          return static_cast<char>(((c - 'A' + shift_amount) % 26) + 'A');
        }
        else if (c >= 'a' && c <= 'z')
        {
          // Shift within lowercase letters
          return static_cast<char>(((c - 'a' + shift_amount) % 26) + 'a');
        }
        else if (c >= '0' && c <= '9')
        {
          // Shift within digits
          return static_cast<char>(((c - '0' + shift_amount) % 10) + '0');
        }
        else
        {
          // Leave other characters unchanged
          return c;
        }
      }

      // Function to shift a character backward within alphanumeric ranges
      constexpr char shift_char_backward(char c, int shift_amount)
      {
        if (c >= 'A' && c <= 'Z')
        {
          // Reverse shift within uppercase letters
          return static_cast<char>(((c - 'A' - shift_amount + 26) % 26) + 'A');
        }
        else if (c >= 'a' && c <= 'z')
        {
          // Reverse shift within lowercase letters
          return static_cast<char>(((c - 'a' - shift_amount + 26) % 26) + 'a');
        }
        else if (c >= '0' && c <= '9')
        {
          // Reverse shift within digits
          return static_cast<char>(((c - '0' - shift_amount + 10) % 10) + '0');
        }
        else
        {
          // Leave other characters unchanged
          return c;
        }
      }

      // Compile-time encryption function
      template <size_t N>
      constexpr Encrypted_String<N> encrypt(const char(&input)[N])
      {
        Encrypted_String<N> result{};

        for (size_t i = 0; i < N - 1; ++i)
        {
          result.data[i] = shift_char_forward(input[i], SMM_STRING_SHIFT_AMOUNT);
        }

        result.data[N - 1] = '\0'; // Ensure null termination
        return result;
      }

      // Runtime decryption function
      template <size_t N>
      std::string decrypt(const Encrypted_String<N>& enc)
      {
        std::string result(N - 1, '\0');

        for (size_t i = 0; i < N - 1; ++i)
        {
          result[i] = shift_char_backward(enc.data[i], SMM_STRING_SHIFT_AMOUNT);
        }

        return result;
      }
    }

#ifdef SMM_WIN_UWP
    // Helper to convert std::string to std::string for UWP specifics
    std::wstring string_to_wstring(const std::string& utf8_string);
#endif

    // Forward declarations internal implementation
    class _Channel;
    class _Client;
    class _Server;
  } // namespace _detail

  // Forward declarations user-interface
  class Client;
  class Server;
  class Connection;
  class Response;
  class Request;

  // Conversion class for all messages.
  // Use this to discern id of message before
  // casting the content buffer to the correct id for reading...
  class Message
  {
  protected:
    enum class Type
    {
      Normal,
      Request,
      Response
    };

    Type type{ Type::Normal };
    int id{ SMM_MESSAGE_ID_UNKNOWN };
    Response* response_address{ nullptr };

    // response_address is not meant to be accessed publicly in the current implementation.
    // The caller will unblock the caller thread/process once
    // the address stored in response_address receives response data.

    char content
      [
        SMM_MESSAGE_SIZE
          - sizeof(type)
          - sizeof(id)
          - sizeof(response_address)

          // Alignment operation for 32-bit <-> 64-bit,
          // since pointer size differs between them.
          -((sizeof(response_address) == 8) ? 4 : 0)
      ]{ 0 };
        // Total content size should be equal to SMM_MESSAGE_SIZE

        template <typename T>
        void set_as(int id, const T& content);

        template <typename T>
        void set_as(int id, Message::Type type, Response* response_address, const T& content);

        template <typename T>
        Message(int id, Message::Type type, Response* response_address, const T& content);

        template <typename T>
        Message(int id, const T& content);

  public:
    int get_id() const;

    template <typename T>
    T get_as() const;

    Message() = default;

    friend class _detail::_Channel;
    friend class _detail::_Client;
    friend class _detail::_Server;

    friend class Request;
    friend class Response;
  };

  // Helper to get user ID of user defined message, at compile time.
  // Useful for switch case statements.
  // Used internally but encouraged to be used by end-users aswell.
  template <typename T>
  inline constexpr int ID()
  {
    return T::_smm_message_id;
  }

  using connection_handler_t = std::function<void(const Connection&)>;
  using disconnection_handler_t = std::function<void(const Client&, int)>;
  using message_handler_t = std::function<void(const Client&, const Message&)>;
  using request_handler_t = std::function<void(const Request&)>;

  class Client
  {
  protected:
    std::shared_ptr<_detail::_Client> shared{ nullptr };

    void send(Message* message) const;
    void send(const Message& message) const;

  public:
    bool is_valid() const;
    bool is_connected() const;
    int get_id() const;
    void disconnect(int reason = SMM_DISCONNECTION_NORMAL) const;

    template <typename T, typename... Args>
    void send(Args&&... args) const;

    template <typename T, typename... Args>
    inline std::optional<Response> send_request(Args&&... args) const;

    Client(const std::shared_ptr<_detail::_Client>& shared);
    Client() = default;

    //friend class Safe_Array;
    friend class Server;
    friend class _detail::_Channel;
    friend class _detail::_Client;
    friend class _detail::_Server;

    friend class Request;
    friend class Response;
  };

  class Server
  {
  protected:
    std::shared_ptr<_detail::_Server> shared{ nullptr };

  public:
    bool is_valid() const;
    bool is_listening() const;
    bool is_open() const;
    std::optional<Client> get_client(int id) const;
    std::vector<Client> get_clients() const;
    const message_handler_t& get_handler() const;

    void on_message(const message_handler_t& message_handler) const;
    void on_request(const request_handler_t& request_handler) const;

    void on_connection(const connection_handler_t& connection_handler) const;
    void on_disconnection(const disconnection_handler_t& disconnection_handler) const;

    bool listen(unsigned int interval = 1) const;
    std::optional<std::shared_future<bool>> listen_async(unsigned int interval = 1) const;

    std::optional<Client> connect(int target_id) const;
    std::optional<std::future<std::optional<Client>>> connect_async(int target_id) const;

    void close(int handle_final_messages_timeout = 0) const;
    std::optional<std::future<void>> close_async(int handle_final_messages_timeout = 0) const;

    bool create(int id, const std::string& name_space) const;
    bool create(int id) const;

    Server(int id, const std::string& name_space);
    Server(int id);
    Server();

    friend class Client;
    friend class _detail::_Channel;
    friend class _detail::_Client;
    friend class _detail::_Server;
  };

  // For handling connections manually
  class Connection
  {
  protected:
    int id{ 0 };
    std::string name_space;
    _detail::_Server* server{ nullptr };

  public:
    int get_id() const;
    const std::string& get_name_space() const;

    std::optional<Client> accept() const;
    void reject() const;

    Connection(int id, const std::string& name_space, _detail::_Server* server) :
      id(id),
      name_space(name_space),
      server(server)
    {
    }

    Connection() = default;

    friend class _detail::_Server;
  };

  // Response wrapper class.
  // Only serves a semantic purpose.
  class Response : public Message
  {
  };

  // Request wrapper class.
  // Each request expects a response in the request handler!
  class Request : public Message
  {
  protected:
    Client client;
    mutable std::atomic<bool> responded{ false };

  public:
    const Client& get_client() const;

    template <typename T, typename... Args>
    void respond(Args&&... args) const;

    Request(const Client& client, const Message& message) :
      Message(message),
      client(client)
    {
    }

    friend class _detail::_Server;
  };

  // Public Messages namespace
  namespace Messages
  {
    // Generic message.
    // End-user can choose to respond with this message directly.
    struct Unknown
    {
      SMM_MESSAGE_ID = SMM_MESSAGE_ID_UNKNOWN;
    };

    // If end-user doesn't respond with a defined message structure, the internal
    // request handler will send this default response message back instead.
    // End-user should not explicitly use this in their code.
    struct No_Response
    {
      SMM_MESSAGE_ID = SMM_MESSAGE_ID_NO_RESPONSE;
    };
  }

  namespace _detail
  {
    // Internal Messages namespace
    namespace Messages
    {
      struct Connection
      {
        SMM_MESSAGE_ID = SMM_MESSAGE_ID_CONNECTION;
        int sender_id{ SMM_SENDER_ID_UNKNOWN };

        Connection(int sender_id) :
          sender_id(sender_id)
        {
        }
      };

      struct Connection_Response
      {
        SMM_MESSAGE_ID = SMM_MESSAGE_ID_CONNECTION_RESPONSE;
        bool success{ false };

        Connection_Response(bool success) :
          success(success)
        {
        }
      };

      struct Disconnection
      {
        SMM_MESSAGE_ID = SMM_MESSAGE_ID_DISCONNECTION;
        int sender_id{ SMM_SENDER_ID_UNKNOWN };
        int reason{ SMM_DISCONNECTION_NORMAL };

        Disconnection(int sender_id, int reason = SMM_DISCONNECTION_NORMAL) :
          sender_id(sender_id),
          reason(reason)
        {
        }
      };
    }

    // Container for message and it's metadata
    struct Message_Packet
    {
      int sender_id{ 0 };
      Message message;
    };

    class _Channel
    {
    protected:
      Semaphore message_signal;
      Shared_Memory shared_memory;
      Shared_Queue<Message_Packet> message_queue;

      // True if CreateEventObject() and CreateMapping() both succeed, false otherwise
      bool channel_created{ false };
      int id{ -1 };
      std::string name_space;

      static std::string create_name(int id, const std::string& name_space, const char* variable);
      bool create_channel(int id, const std::string& name_space);

    public:
      bool is_channel_created() const;
      int get_id() const;
      const std::string& get_name_space() const;
      void close();

      _Channel(int id, const std::string& name_space);
      _Channel() = default;

      friend class Client;
      friend class Server;
      friend class _Client;
      friend class _Server;
    };

    class _Client : public _Channel
    {
    protected:
      std::atomic<bool> connected{ false };
      _Server* server{ nullptr };

      template <typename T>
      Message construct_message(const T& custom_message, Message::Type type, Response* response_address);

      bool open(int id, const std::string& name_space);
      void close();

      template <typename T, typename... Args>
      void _send(Message::Type message_type, Response* response_address, Args&&... args);

    public:
      int get_id() const;
      bool is_connected() const;
      void disconnect(int reason = SMM_DISCONNECTION_NORMAL);

      void send(const Message* message);

      template <typename T, typename... Args>
      void send(Args&&... args);

      template <typename T, typename... Args>
      std::optional<Response> send_request(Args&&... args);

      _Client(int id, const std::string& name_space, _Server* server);

      _Client() = default;
      ~_Client();

      friend class Client;
      friend class Server;
      friend class _Channel;
      friend class _Server;
    };

    class _Server : public _Channel
    {
    protected:
      Semaphore response_signal;
      Semaphore listening_ended_signal;

      std::atomic<bool> listening_loop_running{ false };
      std::atomic<std::thread::id> closing_thread_id;
      std::atomic<std::thread::id> listening_thread_id;
      std::shared_future<bool> listening_thread;

      High_Precision_Timer timer;
      std::atomic<bool> open{ false };

      Safe_Array<Client, SMM_MAX_CLIENTS_PER_SERVER> clients;

      message_handler_t message_handler{ [](const Client&, const Message&) {} };
      request_handler_t request_handler{ [](const Request&) {} };

      connection_handler_t connection_handler;
      disconnection_handler_t disconnection_handler;

      void _message_handler(int sender_id, Message& message);
      void listening_loop(unsigned int interval);
      bool create_local_signaling(int id, const std::string& name_space);

    public:
      bool is_listening() const;
      bool is_open() const;
      std::optional<Client> get_client(int id) const;
      std::vector<Client> get_clients() const;
      const message_handler_t& get_handler() const;

      void on_message(const message_handler_t& message_handler);
      void on_request(const request_handler_t& request_handler);

      void on_connection(const connection_handler_t& connection_handler);
      void on_disconnection(const disconnection_handler_t& disconnection_handler);

      bool listen(unsigned int interval = 1);
      std::optional<std::shared_future<bool>> listen_async(unsigned int interval = 1);

      std::optional<Client> connect(int target_id);
      std::optional<std::future<std::optional<Client>>> connect_async(int target_id);

      void close(int handle_final_messages_timeout = 0);
      std::optional<std::future<void>> close_async(int handle_final_messages_timeout = 0);

      bool create(int id, const std::string& name_space);
      bool create(int id);

      _Server(int id, const std::string& name_space);
      _Server(int id);

      _Server& operator=(const _Server&) = delete;
      _Server& operator=(_Server&& other) noexcept;
      _Server(const _Server&) = delete;
      _Server(_Server&& other) noexcept;
      _Server() = default;

      ~_Server();

      friend class Client;
      friend class Server;
      friend class Connection;

      friend class _Channel;
      friend class _Client;
    };
  } // namespace _detail

  namespace _detail
  {
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

#ifdef _WIN32
    inline void CALLBACK High_Precision_Timer::timer_proc(UINT u_timer_id, UINT u_msg, DWORD_PTR dw_user, DWORD_PTR dw1, DWORD_PTR dw2)
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
    inline HANDLE Semaphore::get_object() const
#else
    inline sem_t* Semaphore::get_object() const
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

      // Release any blocked threads.
      this->increment(Semaphore::max_count);

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

    inline bool Semaphore::increment(int count) const
    {
      if (this->object == nullptr)
      {
        return false;
      }

#ifdef _WIN32
      return ReleaseSemaphore(this->object, count, nullptr);
#else
      bool success = true;

      for (int i = 0; i < count; ++i)
      {
        if (sem_post(this->object) != 0)
        {
          success = false;
        }
      }

      return success;
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
      //TODO: Handle errors. GetLastError()
#endif
       //return this->file_mapping != nullptr;

      if (!this->file_mapping)
      {
        return false;
      }
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

    inline std::string _Channel::create_name(int id, const std::string& name_space, const char* variable)
    {
      std::string id_string = std::to_string(id);
      std::string slash;

      if (name_space.empty())
      {
        slash = "";
      }
      else
      {
#ifdef _WIN32;
        slash = "\\";
#else
        slash = "/";
#endif
      }

#ifdef SMM_DOMAIN
      std::string channel_string = name_space + slash + string::encrypt(SMM_DOMAIN).get() + "." + id_string + "." + variable;
#else
      std::string channel_string = name_space + slash + id_string + "." + variable;
#endif
      return channel_string;
    }

    // Create communication channel (event object and shared memory)
    // This should only be called once.
    // Check is_channel_created() to see if that's the case.
    inline bool _Channel::create_channel(int id, const std::string& name_space)
    {
      // Construct mapping and semaphore id strings.
      // By accepting namespaces we can connect to pre-defined UWP sandboxes.

      std::string file_mapping_name = _Channel::create_name(id, name_space, string::encrypt("mapping").get());
      std::string message_name = _Channel::create_name(id, name_space, string::encrypt("message").get());

      constexpr std::size_t shared_memory_size =
        Shared_Queue<Message_Packet>::get_control_block_size()
        + SMM_MESSAGE_SIZE
        * SMM_MAX_QUEUE_CAPACITY;

      if (!this->shared_memory.create(file_mapping_name, shared_memory_size))
      {
        return false;
      }

      if (!this->message_signal.create(message_name))
      {
        return false;
      }

      // Create a message queue in the newly created shared memory
      this->message_queue.create(this->shared_memory.get_address(), shared_memory_size);

      // Success! We should now have 'shared memory' communication ready to go.
      this->id = id;
      this->name_space = name_space;
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

    inline const std::string& _Channel::get_name_space() const
    {
      return this->name_space;
    }

    inline void _Channel::close()
    {
      this->shared_memory.close();
      this->message_signal.close();
    }

    // ID must be unique
    inline _Channel::_Channel(int id, const std::string& name_space)
    {
      this->create_channel(id, name_space);
    }
  } // namespace _detail

  inline int Message::get_id() const
  {
    return this->id;
  }

  // TODO: Return reference here instead of returning a fully constructed new object instance??
  template <typename T>
  inline T Message::get_as() const
  {
    // Reinterpret to const to respect const nature of this function,
    // and to allow this to work in functions that accept "const Message&"
    return *reinterpret_cast<const T*>(this->content);
  }

  template <typename T>
  inline void Message::set_as(int id, const T& content)
  {
    this->id = id;
    *reinterpret_cast<T*>(this->content) = content;
  }

  template <typename T>
  inline void Message::set_as(int id, Message::Type type, Response* response_address, const T& content)
  {
    this->type = type;
    this->response_address = response_address;
    this->set_as<T>(id, content);
  }

  template <typename T>
  inline Message::Message(int id, Message::Type type, Response* response_address, const T& content)
  {
    this->set_as<T>(id, type, response_address, content);
  }

  template <typename T>
  inline Message::Message(int id, const T& content)
  {
    this->set_as<T>(id, content);
  }

  // Returns true if underlying shared_ptr points to a valid _Client
  inline bool Client::is_valid() const
  {
    return (this->shared != nullptr);
  }

  inline bool Client::is_connected() const
  {
    return this->shared->is_connected();
  }

  inline int Client::get_id() const
  {
    return this->shared->get_id();
  }

  inline void Client::disconnect(int reason) const
  {
    this->shared->disconnect(reason);
  }

  inline void Client::send(Message* message) const
  {
    this->shared->send(message);
  }

  inline void Client::send(const Message& message) const
  {
    this->shared->send(&message);
  }

  template <typename T, typename... Args>
  inline void Client::send(Args&&... args) const
  {
    this->shared->send<T>(std::forward<Args>(args)...);
  }

  template <typename T, typename... Args>
  inline std::optional<Response> Client::send_request(Args&&... args) const
  {
    return this->shared->send_request<T>(std::forward<Args>(args)...);
  }

  inline Client::Client(const std::shared_ptr<_detail::_Client>& shared)
  {
    this->shared = shared;
  }

  // Returns true if underlying shared_ptr points to a valid _Server
  inline bool Server::is_valid() const
  {
    return (this->shared != nullptr);
  }

  inline bool Server::is_listening() const
  {
    return this->shared->is_listening();
  }

  inline bool Server::is_open() const
  {
    return this->shared->is_open();
  }

  inline std::optional<Client> Server::get_client(int id) const
  {
    return this->shared->get_client(id);
  }

  inline std::vector<Client> Server::get_clients() const
  {
    return this->shared->get_clients();
  }

  inline const message_handler_t& Server::get_handler() const
  {
    return this->shared->get_handler();
  }

  inline void Server::on_message(const message_handler_t& message_handler) const
  {
    this->shared->on_message(message_handler);
  }

  inline void Server::on_request(const request_handler_t& request_handler) const
  {
    this->shared->on_request(request_handler);
  }

  inline void Server::on_connection(const connection_handler_t& connection_handler) const
  {
    this->shared->on_connection(connection_handler);
  }

  inline void Server::on_disconnection(const disconnection_handler_t& disconnection_handler) const
  {
    this->shared->on_disconnection(disconnection_handler);
  }

  inline bool Server::listen(unsigned int interval) const
  {
    return this->shared->listen(interval);
  }

  inline std::optional<std::shared_future<bool>> Server::listen_async(unsigned int interval) const
  {
    return this->shared->listen_async(interval);
  }

  inline std::optional<Client> Server::connect(int target_id) const
  {
    return this->shared->connect(target_id);
  }

  inline std::optional<std::future<std::optional<Client>>> Server::connect_async(int target_id) const
  {
    return this->shared->connect_async(target_id);
  }

  inline void Server::close(int handle_final_messages_timeout) const
  {
    this->shared->close(handle_final_messages_timeout);
  }

  inline std::optional<std::future<void>> Server::close_async(int handle_final_messages_timeout) const
  {
    return this->shared->close_async(handle_final_messages_timeout);
  }

  inline bool Server::create(int id, const std::string& name_space) const
  {
    return this->shared->create(id, name_space);
  }

  inline bool Server::create(int id) const
  {
    return this->shared->create(id);
  }

  inline Server::Server(int id, const std::string& name_space)
  {
    // TODO:
    //  Maybe first check a global fixed sized shared memory block to see if client with specific ID already exists?
    //  ^ Would this even work with UWP?

    this->shared = std::make_shared<_detail::_Server>(id, name_space);

    if (!this->shared->open.load())
    {
      this->shared = nullptr;
    }
  }

  inline Server::Server(int id)
  {
    this->shared = std::make_shared<_detail::_Server>(id);

    if (!this->shared->open.load())
    {
      this->shared = nullptr;
    }
  }

  inline Server::Server()
  {
    // Must create shared even for a default initialization
    this->shared = std::make_shared<_detail::_Server>();
  }

  inline int Connection::get_id() const
  {
    return this->id;
  }

  inline const std::string& Connection::get_name_space() const
  {
    return this->name_space;
  }

  inline std::optional<Client> Connection::accept() const
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
    auto& new_client = this->server->clients.insert(std::make_shared<_detail::_Client>(this->id, this->name_space, this->server))->value;

    // Send success response to connecting client, and signal-it to wake up connecting client's thread
    new_client.send<_detail::Messages::Connection_Response>(true);

    return new_client;
  }

  inline void Connection::reject() const
  {
    // Nothing here for now. This used to update the handled state
    // but the current implementation doesn't need it anymore.

    // TODO:
    //  Send connection rejected response message to handle cases where
    //  client is already connected?
  }

  inline const Client& Request::get_client() const
  {
    return this->client;
  }

  template <typename T, typename... Args>
  inline void Request::respond(Args&&... args) const
  {
    T response(std::forward<Args>(args)...);
    Message message(ID<T>(), Message::Type::Response, this->response_address, response);
    // or this->client.construct_message<T>(...);

    this->client.send(&message);
    this->responded.store(true);
  }

  namespace _detail
  {
    // Helper to construct message depending on if send or send_request is called.
    template <typename T>
    inline Message _Client::construct_message(const T& custom_message, Message::Type type, Response* response_address)
    {
      Message message;

      if (!response_address)
      {
        message.set_as<T>(ID<T>(), custom_message);
      }
      else
      {
        message.set_as<T>(ID<T>(), type, response_address, custom_message);
      }

      return message;
    }

    inline bool _Client::open(int id, const std::string& name_space)
    {
      if (this->create_channel(id, name_space))
      {
        this->connected.store(true);
        return true; // Success
      }

      return false; // Error
    }

    inline void _Client::close()
    {
      if (this->connected.load())
      {
        this->disconnect();
      }

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
      this->send<Messages::Disconnection>(this->server->id, reason);

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

    inline void _Client::send(const Message* message)
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
      this->message_signal.increment();
    }

    template <typename T, typename... Args>
    inline void _Client::_send(Message::Type message_type, Response* response_address, Args&&... args)
    {
      constexpr int id = ID<T>();

      if constexpr (sizeof...(Args) == 1)
      {
        using Arg_T = std::decay_t<std::tuple_element_t<0, std::tuple<Args...>>>;

        if constexpr (std::is_same_v<T, Arg_T>)
        {
          // Extract first argument of type T, and send it.
          // No need to construct it like the branch below because the message is already complete.
          // This effectively works as a 'const T&' variant of the send function.
          auto&& custom_message = std::get<0>(std::forward_as_tuple(args...));
          Message message = this->construct_message<T>(custom_message, message_type, response_address);
          this->send(&message);

          return;
        }
      }

      // Construct custom message with expected arguments, and send it.
      // Check constructor of T to see what arguments to pass.
      T custom_message(std::forward<Args>(args)...);
      Message message = this->construct_message<T>(custom_message, message_type, response_address);
      this->send(&message);

      return;
    }

    template <typename T, typename... Args>
    inline void _Client::send(Args&&... args)
    {
      this->_send<T>(Message::Type::Normal, nullptr, std::forward<Args>(args)...);
    }

    template <typename T, typename... Args>
    inline std::optional<Response> _Client::send_request(Args&&... args)
    {
      Response response;

      // This function expects a response which means that the message listening loop must be running
      // to send a message first, else we will never receive the response and unblock this thread
      // blocked by this function.
      if (!this->server->listening_loop_running.load())
      {
        return std::nullopt;
      }

      this->_send<T>(Message::Type::Request, &response, std::forward<Args>(args)...);

      // while (response.get_id() == SMM_MESSAGE_ID_UNKNOWN)
      while (response.response_address == nullptr)
      {
        // TODO: Proper timeout
        this->server->response_signal.wait(INFINITE);
      }

      return response;
    }

    // This is not meant to be called by end-users.
    inline _Client::_Client(int id, const std::string& name_space, _Server* server) :
      server(server)
    {
      this->open(id, name_space);
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

          Connection connection_attempt(sender_id, this->name_space, this);

          if (this->connection_handler)
          {
            this->connection_handler(connection_attempt);
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
            int reason = message.get_as<Messages::Disconnection>().reason;
            this->disconnection_handler(sender, reason);
          }

          // Finally remove from our list
          sender.shared->connected.store(false);
          this->clients.erase(client_exists->index);
          break;
        }

        // Not an internal message, redirect to user-specified message/request handler
        default:
        {
          if (!client_exists)
          {
            break;
          }

          switch (message.type)
          {
            case Message::Type::Normal:
            {
              this->message_handler(sender, message);
              break;
            }
            case Message::Type::Request:
            {
              Request request(sender, message);
              this->request_handler(request);

              // If user doesn't explicitly respond with a defined message structure
              // in the user-assigned request handler, then we must respond with a generic message here instead.
              // We must do this to unblock the thread of the sender (blocked by send_request).
              if (!request.responded.load())
              {
                request.respond<smm::Messages::No_Response>();
              }

              break;
            }
            case Message::Type::Response:
            {
              // Store message in response address.
              // This cast is fine because Response extends from Message,
              // but adds no additional members to the class (empty body).
              *message.response_address = *static_cast<Response*>(&message);

              // Send signal to release sender's blocked thread (at send_request)
              this->response_signal.increment(Semaphore::max_count);
              break;
            }
          }

          break;
        }
      }
    }

    // Main message loop for this client.
    // This function waits for messages from other processes, deqeueues them from shared-memory
    // and relays them to the user-specified message handler.
    inline void _Server::listening_loop(unsigned int interval)
    {
      while (this->listening_loop_running.load())
      {
        // Wait for a message
        this->timer.sleep(interval);
        this->message_signal.wait(INFINITE);

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

      // Notify the waiting thread that listening is done,
      // make sure notification isn't sent from the same thread to avoid deadblocks.
      // Currently only the close() function can stop the listening loop,
      // so the the comparison below is fine.
      if (this->listening_thread_id.load() != this->closing_thread_id.load())
      {
        this->listening_ended_signal.increment();
      }
    }

    // Signaling exclusive to _Server (Shared signaling for both _Client and _Server are in _Channel).
    inline bool _Server::create_local_signaling(int id, const std::string& name_space)
    {
      std::string response_name = _Channel::create_name(id, name_space, string::encrypt("response").get());
      std::string listening_ended_name = _Channel::create_name(id, name_space, string::encrypt("listening:end").get());

      if (!this->response_signal.create(response_name))
      {
        return false;
      }

      if (!this->listening_ended_signal.create(listening_ended_name))
      {
        return false;
      }

      return true;
    }

    // Use this in combination with is_channel_created() to (for example)
    // check if the current client object can be reassigned to a new channel
    inline bool _Server::is_listening() const
    {
      return this->listening_loop_running.load();
    }

    inline bool _Server::is_open() const
    {
      return this->open.load();
    }

    inline std::optional<Client> _Server::get_client(int id) const
    {
      auto& safe_clients = this->clients;
      std::size_t capacity = safe_clients.capacity();

      for (int i = 0; i < capacity; ++i)
      {
        auto client_exists = safe_clients.at(i);

        if (client_exists && client_exists->value.get_id() == id)
        {
          return client_exists->value; // Client
        }
      }

      // No client found, return falsy
      return std::nullopt;
    }

    // Converts Safe_Array to vector for idiomatic usage
    inline std::vector<Client> _Server::get_clients() const
    {
      std::vector<Client> clients;

      auto& safe_clients = this->clients;
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

    // This can be used to check if a handler is already set
    inline const message_handler_t& _Server::get_handler() const
    {
      return this->message_handler;
    }

    inline void _Server::on_message(const message_handler_t& message_handler)
    {
      this->message_handler = message_handler;
    }

    inline void _Server::on_request(const request_handler_t& request_handler)
    {
      this->request_handler = request_handler;
    }

    inline void _Server::on_connection(const connection_handler_t& connection_handler)
    {
      this->connection_handler = connection_handler;
    }

    inline void _Server::on_disconnection(const disconnection_handler_t& disconnection_handler)
    {
      this->disconnection_handler = disconnection_handler;
    }

    // This function or it's async variant must be called before connecting or sending messages
    inline bool _Server::listen(unsigned int interval)
    {
      if (!this->open.load())
      {
        return false;
      }

      this->listening_thread_id.store(std::this_thread::get_id());
      this->listening_loop_running.store(true);
      this->listening_loop(interval);

      return true;
    }

    inline std::optional<std::shared_future<bool>> _Server::listen_async(unsigned int interval)
    {
      // Only spawn a new thread if not already running
      if (this->listening_loop_running.load())
      {
        return std::nullopt;
      }

      // Launch async operation and store shared future
      this->listening_thread = std::async(std::launch::async, &_Server::listen, this, interval).share();
      return this->listening_thread;
    }

    // Connects to a given server. Only connects to servers in the same namespace.
    inline std::optional<Client> _Server::connect(int target_id)
    {
      if (!this->open.load())
      {
        return std::nullopt;
      }

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
      Client new_client(std::make_shared<_Client>(target_id, this->name_space, this));

      // Send our id to new_client in connection message
      new_client.send<Messages::Connection>(this->id);

      // Temporary wrapper
      struct Hostage
      {
        Message_Packet data;
        bool important = false;
      };

      std::vector<Hostage> hostages;

      while (true)
      {
        this->message_signal.wait(INFINITE); // Wait for message signal to avoid busy waiting
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

        auto response = hostage.data.message.get_as<Messages::Connection_Response>();

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

    inline std::optional<std::future<std::optional<Client>>> _Server::connect_async(int target_id)
    {
      if (!this->open.load())
      {
        return std::nullopt;
      }

      return std::async(std::launch::async, &_Server::connect, this, target_id);
    }

    inline void _Server::close(int handle_final_messages_timeout)
    {
      if (!this->open.load()
        || this->closing_thread_id.load() != std::thread::id())
        // Some thread already called close() ^
      {
        return;
      }

      this->closing_thread_id.store(std::this_thread::get_id());

      // Mark as closed to disallow more sends
      this->open.store(false);

      if (handle_final_messages_timeout > 0)
      {
        // Remaining messages should only be handled if close() is called from
        // a separate thread, otherwise the thread will deadblock.
        if (this->closing_thread_id.load() != this->listening_thread_id.load())
        {
          // Wait until remaining messages in message_queue are processed (until timeout)
          constexpr int sleep_time = 10;
          int time_passed = 0;

          while (!this->message_queue.is_empty())
          {
            if (time_passed >= handle_final_messages_timeout)
            {
              break;
            }

            this->timer.sleep(sleep_time); // Sleep to avoid busy waiting
            time_passed += sleep_time;
          }
        }
      }

      // Signal message thread to terminate
      this->listening_loop_running.store(false);
      this->message_signal.increment();

      if (this->closing_thread_id.load() != this->listening_thread_id.load())
      {
        this->listening_ended_signal.wait();
      }

      // Disconnect all clients in clients list.
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

    inline std::optional<std::future<void>> _Server::close_async(int handle_final_messages_timeout)
    {
      if (!this->open.load())
      {
        return std::nullopt;
      }

      return std::async(std::launch::async, &_Server::close, this, handle_final_messages_timeout);
    }

    inline bool _Server::create(int id, const std::string& name_space)
    {
      // Only closed instances can create a channel.
      if (this->open.load())
      {
        return false;
      }

      if (!this->create_channel(id, name_space))
      {
        return false;
      }

      if (!this->create_local_signaling(id, name_space))
      {
        return false;
      }

      this->open.store(true);
      return true; // Success!
    }

    inline bool _Server::create(int id)
    {
      return this->create(id, "");
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

        this->listening_loop_running.store(other.listening_loop_running.load());

        // Reset other to indicate moved-from state
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
      this->listening_loop_running.store(other.listening_loop_running.load());

      // Reset other to indicate moved-from state
      other.listening_loop_running.store(false);
    }

    inline _Server::_Server(int id, const std::string& name_space)
    {
      this->create(id, name_space);
    }

    inline _Server::_Server(int id)
    {
      this->create(id);
    }

    inline _Server::~_Server()
    {
      this->close(2048);
    }
  } // namespace _detail

} // namespace smm

#endif // SMM_SHARED_MEMORY_MESSAGER_H
