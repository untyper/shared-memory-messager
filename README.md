# shared-memory-messager

## How to use
1. Include in project
2. Define types for abstract communication

```c++
enum Message_Type
{
  DEBUG_LOG = 0xFF,
  // ...
  // More message types here
};

struct Debug_Log
{
  char text[1024] = {};
};

// ...
// More message structs here
```
3. Create communication channel and register message handler

```c++
void message_handler(Message message)
{
  switch (message.get_type())
  {
    case DEBUG_LOG:
    {
      auto content = message.get_content_as<Debug_Log>();
      std::cout << "Debug message from another process: " << content.text << std::endl;
      break;
    }
  }
}

Message_Thread smm(L"my-first-channel"); // or smm.create_channel(L"my-first-channel");
smm.set_handler(message_handler);
```

4. Send message to another process that has also created/opened the same message channel

```c++
std::wstring text = L"Hello world!";
Debug_Log content;

// Copy data from paremeter to DebugLog object
for (int i = 0; i < text.size(); i++)
{
  content.text[i] = text[i];
}

// Finally send message to the other process
smm.send({DEBUG_LOG, content});
```

## Remarks
- For each type defined in the enum there must be a corresponding struct type. The type doesn't have to be defined within an enum, it can be a standalone integer too.
- Data in the shared memory cannot be dereferenced in the receiving procesess and thus cannot be a pointer(s).
- Pointers can still be passed as data if the intent is to dereference it in the originating process later.
- UWP and Win32 apps use different API's for event creation and file mapping and therefore versions for both are provided within their respective folders in `src`.
