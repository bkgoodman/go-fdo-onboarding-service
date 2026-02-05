# go-fdo Library Logging Issue Report

## Summary
Applications using the go-fdo library cannot disable debug output, even when explicitly configuring the slog logger to INFO level or higher. This is caused by tightly-coupled global mutable state in the library's example code that forces debug logging globally.

## Root Cause Analysis

### 1. Global Mutable Logger State (`go-fdo/examples/cmd/log.go`)
```go
var level slog.LevelVar

func init() {
    slog.SetDefault(slog.New(devlog.NewHandler(os.Stdout, &devlog.Options{
        Level: &level,  // Mutable global level
    })))
}
```

**Problem**: This `init()` function runs when ANY package in `examples/cmd` is imported, creating a global logger with a mutable `LevelVar` that persists for the entire application lifetime.

### 2. Example Code Forces Debug Globally (`go-fdo/examples/cmd/server.go`)
```go
if debug {
    level.Set(slog.LevelDebug)  // Sets global level to DEBUG
}
```

**Problem**: The example code calls `level.Set(slog.LevelDebug)` which modifies the global mutable state. This affects ALL applications using the library, not just the example.

### 3. Debug Check Uses Global State (`go-fdo/http/debug.go`)
```go
func debugEnabled() bool {
    return slog.Default().Enabled(context.Background(), slog.LevelDebug)
}
```

**Problem**: This function checks if DEBUG is enabled on the current default logger, but the logger was already set to DEBUG by the example code's `init()` function.

### 4. HTTP Dumping Uses Debug Check (`go-fdo/http/util.go`)
```go
func debugRequest(w http.ResponseWriter, r *http.Request, handler http.HandlerFunc) {
    if !debugEnabled() {
        handler.ServeHTTP(w, r)
        return
    }
    slog.Debug("request", "dump", ...)  // Dumps all HTTP traffic
    slog.Debug("response", "dump", ...)
}
```

**Problem**: If `debugEnabled()` returns true (which it does due to step 2), ALL HTTP traffic is logged, and applications cannot disable this.

## Why Application-Level Fixes Don't Work

1. **Timing**: The `init()` function in `log.go` runs when the package is imported, before the application's `main()` function
2. **Global State**: The `level.Set()` call modifies a global `LevelVar` that persists across the entire application
3. **Logger Instance**: Calling `slog.SetDefault()` in the application doesn't affect the logger instance created by the library's `init()` function
4. **Coupling**: The library's debug output is tightly coupled to example code, not to the application's logging configuration

## Impact

- Applications cannot control the verbosity of go-fdo library output
- Debug HTTP dumps are forced on, making it difficult to see application-level logs
- No way to disable this behavior without modifying the library itself

## Recommended Fix

### Option 1: Remove Global Logger Setup from Examples
Move the logger setup OUT of `examples/cmd/log.go` and into each example's `main()` function. This prevents the global state from affecting applications using the library.

### Option 2: Make Debug Output Configurable
Provide a public API to control debug output:
```go
package http

var debugOutput = false

func SetDebugOutput(enabled bool) {
    debugOutput = enabled
}

func debugEnabled() bool {
    return debugOutput && slog.Default().Enabled(context.Background(), slog.LevelDebug)
}
```

### Option 3: Respect Application Logger Configuration
Check if a logger has already been set before creating a new one:
```go
func init() {
    // Only set default if one hasn't been set already
    if slog.Default() == slog.Default() {
        slog.SetDefault(slog.New(devlog.NewHandler(os.Stdout, &devlog.Options{
            Level: &level,
        })))
    }
}
```

## Workaround for Applications

Until the library is fixed, applications can work around this by:
1. Filtering output at the shell level: `./app 2>&1 | grep -v "level=DEBUG"`
2. Redirecting stderr to /dev/null (loses all error messages)
3. Modifying the library locally (not recommended)

## Conclusion

The go-fdo library's logging design violates the principle of separation of concerns by coupling library code to example code through global mutable state. Applications should be able to control their own logging configuration without interference from library examples.
