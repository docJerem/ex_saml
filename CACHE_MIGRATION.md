# Cache Migration: Old ex_saml vs New ex_saml

## Context

The old `ex_saml` (in `cryptr_platform_beta`) used **Nebulex caches as direct child processes**
in the supervision tree. The new `ex_saml` (library version) uses a **delegate pattern** where
the cache module is injected via application config (`config :ex_saml, cache: MyApp.Cache`).

This document describes what's missing and what changed.

---

## What's Missing

### 1. `ExSaml.AuthorizationCodeCache` — Module does not exist

**Old version** (`cryptr_platform_beta/apps/ex_saml/lib/ex_saml/caches/authorization_code_cache.ex`):

```elixir
defmodule ExSaml.AuthorizationCodeCache do
  use Nebulex.Cache,
    otp_app: :ex_saml,
    adapter: Nebulex.Adapters.Local

  def ttl, do: :timer.seconds(30)
end
```

This was a Nebulex cache started as a supervised child in `ExSaml.Application`. It provided:
- `put/3` — store an authorization code with TTL
- `take/1` — atomically get + delete (from Nebulex.Cache behaviour)
- `put_new!/2` — store only if key doesn't exist
- `get/1` — retrieve without deletion
- `ttl/0` — returns 30 seconds

**Used by `saml_web`:**
- `SigninController.create/2` — `take(code)` to consume an authorization code
- `SigninController.callback/2` — `take(code)` same usage
- `SigninController.maybe_redirect/4` — `put(code, resp, ttl: ttl())` to store a code

**Status in new ex_saml:** Not created. The module is completely absent.

---

### 2. `ExSaml.AssertionCache.take/1` — Function does not exist

**Old version** (`cryptr_platform_beta/apps/ex_saml/lib/ex_saml/caches/assertion_cache.ex`):

```elixir
defmodule ExSaml.AssertionCache do
  use Nebulex.Cache,
    otp_app: :ex_saml,
    adapter: Nebulex.Adapters.Local
end
```

This was a Nebulex cache — `take/1` came from the `Nebulex.Cache` behaviour automatically.

**New version** (`ex_saml/lib/ex_saml/caches/assertion_cache.ex`):

```elixir
defmodule ExSaml.AssertionCache do
  def all(query, opts \\ []), do: assertion_cache().all(query, opts)
  def ttl(key), do: assertion_cache().ttl(cache_key(key))
  def get(key), do: assertion_cache().get(cache_key(key))
  def put(key, assertion, ttl: ttl), do: assertion_cache().put(cache_key(key), assertion, ttl: ttl)
  def delete(key), do: assertion_cache().delete(cache_key(key))
  defp assertion_cache, do: Application.get_env(:ex_saml, :cache)
  defp cache_key(key), do: {__MODULE__, key}
end
```

The new version is a **delegate module** that proxies to a user-configured cache. It has
`get/1`, `put/3`, `delete/1`, `all/2`, `ttl/1` — but **no `take/1`**.

**Used by `saml_web`:**
- `PageController.maybe_assign_assertion/1` — `take(assertion_key)` to consume assertion
- `SigninController.maybe_assign_assertion/1` — same

**Status in new ex_saml:** Module exists but `take/1` is missing.

---

### 3. `ExSaml.Application` — Caches not started in supervision tree

**Old version** started all three caches as supervised children:

```elixir
children = [
  {ExSaml.Provider, []},
  {ExSaml.BoostrapProvidersLoader, []},
  ExSaml.AssertionCache,        # Nebulex process
  ExSaml.RelayStateCache,       # Nebulex process
  ExSaml.AuthorizationCodeCache # Nebulex process
]
```

**New version** does not start any Nebulex caches (uses delegate pattern instead):

```elixir
children = [
  {ExSaml.Core.TableOwner, []},
  {ExSaml.Provider, []},
  {ExSaml.BoostrapProvidersLoader, []}
]
```

The host application is expected to start its own Nebulex cache and configure it via:

```elixir
config :ex_saml, cache: MyApp.SamlCache
```

---

## Architecture Difference

| Aspect | Old (umbrella) | New (library) |
|--------|---------------|---------------|
| Cache ownership | ex_saml owns and starts Nebulex caches | Host app owns the cache |
| Cache type | 3 separate Nebulex caches | 1 shared cache, namespaced by key prefix |
| `take/1` | Provided by Nebulex.Cache behaviour | Must be delegated manually |
| AuthorizationCodeCache | Built-in Nebulex cache | Not implemented |
| Configuration | Implicit (caches auto-start) | Explicit (`config :ex_saml, cache: ...`) |

---

## Fix Plan

### Option A: Add missing features to the delegate modules (recommended)

Keep the delegate pattern but add the missing pieces:

1. **Add `take/1` to `AssertionCache`** — get + delete atomically:

```elixir
def take(key) do
  cache = assertion_cache()
  ck = cache_key(key)
  value = cache.get(ck)
  if value, do: cache.delete(ck)
  value
end
```

2. **Create `AuthorizationCodeCache`** as a delegate module (same pattern as AssertionCache):

```elixir
defmodule ExSaml.AuthorizationCodeCache do
  def ttl, do: :timer.seconds(30)
  def get(key), do: cache().get(cache_key(key))
  def put(key, value, opts), do: cache().put(cache_key(key), value, opts)
  def take(key) do
    ck = cache_key(key)
    value = cache().get(ck)
    if value, do: cache().delete(ck)
    value
  end
  def put_new!(key, value, opts) do
    ck = cache_key(key)
    if cache().get(ck), do: raise(Nebulex.KeyAlreadyExistsError, key: ck)
    cache().put(ck, value, opts)
  end
  defp cache, do: Application.get_env(:ex_saml, :cache)
  defp cache_key(key), do: {__MODULE__, key}
end
```

3. **Host app** must provide a single Nebulex cache and configure it.

### Option B: Revert to Nebulex-owned caches

Bring back the 3 separate Nebulex caches and start them in `ExSaml.Application`. This matches
the old architecture but couples the library to a specific cache implementation.

---

## Host App Configuration (for Option A)

The host application needs:

```elixir
# In the host app
defmodule MyApp.SamlCache do
  use Nebulex.Cache,
    otp_app: :my_app,
    adapter: Nebulex.Adapters.Local
end

# In config.exs
config :ex_saml, cache: MyApp.SamlCache

# In application.ex supervision tree
children = [
  MyApp.SamlCache,
  # ... other children
]
```
