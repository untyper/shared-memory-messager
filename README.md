# Shared‐Memory Messager (smm)

Cross-process IPC over named shared memory + semaphores  
Supports Windows (including UWP sandbox) and Unix.

## Public API

```cpp
// Server
class smm::Server
{
public:
  bool create(int id) const;
  void on_connection(smm::connection_handler_t) const;
  void on_disconnection(smm::disconnection_handler_t) const;
  void on_message(smm::message_handler_t) const;
  void on_request(smm::request_handler_t) const;
  bool listen(unsigned int interval = 1) const;
  bool listen_async(unsigned int interval = 1) const;
  std::optional<smm::Client> connect(int target_id) const;
  std::optional<std::future<std::optional<Client>>> connect_async(int target_id) const;
  void close(int handle_final_messages_timeout = 0) const;
  std::optional<std::future<void>> close_async(int handle_final_messages_timeout = 0) const;
};

// Client
class smm::Client
{
public:
  bool is_valid() const;
  bool is_connected() const;
  int  get_id() const;
  
  template <typename T, typename... Args>
  void send(Args&&...) const;

  template <typename T, typename... Args>
  std::optional<smm::Response> send_request(Args&&...) const;

  void disconnect(int reason = SMM_DISCONNECTION_NORMAL) const;
};

// Helpers
template <typename T>
inline constexpr int smm::ID();  // get compile-time message ID
````

## Usage Examples

### Simple Ping–Pong

```cpp
// Define messages:
namespace Messages
{
  struct Ping  { SMM_MESSAGE_ID = 1; /* no payload */ };
  struct Pong  { SMM_MESSAGE_ID = 2; /* no payload */ };
}

// — Server side (process A) —
smm::Server srv;
srv.create(1);

// handle incoming Ping requests and respond with Pong
srv.on_request([](const smm::Request& req)
{
  if (req.get_id() == smm::ID<Messages::Ping>())
  {
    req.respond<Messages::Pong>();
  }
});

srv.listen_async(1 /*poll ms*/);


// — Client side (process B) —
smm::Server cli;
cli.create(2);

// connect & send Ping, await Pong
auto maybeClient = cli.connect(1);

if (auto client = maybeClient)
{
  auto maybeResp = client->send_request<Messages::Ping>({});

  if (maybeResp && maybeResp->get_id() == smm::ID<Messages::Pong>())
  {
    // got Pong!
  }
}
```

## Notes

* No need to `listen()` before `connect()`—`connect()` blocks internally until handshake completes.
* For one-way fire-and-forget, use **`on_message` + `send<>()`**.

## Caveats

* Fixed message size (`SMM_MESSAGE_SIZE`, default 4096 B).
* Fixed queue capacity (`SMM_MAX_QUEUE_CAPACITY`, default 16).
* Must call `close()` before exiting to clean up.
* UWP: namespaces correspond to AppContainer paths.

## License

* MIT
