-- Counter decision script: evaluate every bucket, commit only when no
-- enforcing bucket refuses; a shadow bucket commits only when its own verdict
-- allows. All arithmetic is integer microseconds of Unix time -- exact in Lua
-- doubles -- and must match the in-memory reference implementation
-- (engine/store/memory) formula for formula; the differential test holds the
-- two together.
--
-- KEYS: bucket keys, all in one slot (the domain hash tag guarantees it)
-- ARGV[1]: "decide" | "peek"
-- ARGV[2]: cost
-- then 5 values per bucket: algorithm id, p1, p2, p3, shadow(0|1)
--   gcra  (id 1): p1 = emission_us, p2 = tau_us,   p3 = burst
--   fixed (id 2): p1 = period_us,   p2 = requests, p3 = unused
--
-- Reply, flat array of integers: [admitted(0|1)], then 5 per bucket:
--   allowed(0|1), cost_exceeds(0|1), remaining, retry_after_us (-1 when no
--   retry hint applies), reset_after_us

local t = redis.call('TIME')
local now = t[1] * 1000000 + t[2]

local mode = ARGV[1]
local cost = tonumber(ARGV[2])
local n = #KEYS

local allowed = {}
local exceeds = {}
local shadow = {}
local remain_charged = {}
local remain_current = {}
local retry = {}
local reset_charged = {}
local reset_current = {}
local next_state = {}
local next_ttl_ms = {}

local admitted = 1

for i = 1, n do
  local base = 2 + (i - 1) * 5
  local alg = tonumber(ARGV[base + 1])
  local p1 = tonumber(ARGV[base + 2])
  local p2 = tonumber(ARGV[base + 3])
  local p3 = tonumber(ARGV[base + 4])
  shadow[i] = ARGV[base + 5] == '1'

  local state = redis.call('GET', KEYS[i])

  if alg == 1 then
    local emission, tau, burst = p1, p2, p3
    local tat = now
    if state then
      local stored = tonumber(state)
      if stored and stored > now then tat = stored end
    end
    local depth = tat - now
    local current = math.floor((tau - depth) / emission)
    if current < 0 then current = 0 end
    remain_current[i] = current
    reset_current[i] = depth

    if cost > burst then
      allowed[i] = false
      exceeds[i] = true
      retry[i] = -1
      remain_charged[i] = 0
      reset_charged[i] = depth
    else
      local increment = emission * cost
      local new_tat = tat + increment
      local diff = now - (new_tat - tau)
      allowed[i] = diff >= 0
      exceeds[i] = false
      local rc = math.floor(diff / emission)
      if rc < 0 then rc = 0 end
      remain_charged[i] = rc
      reset_charged[i] = new_tat - now
      if allowed[i] then retry[i] = -1 else retry[i] = -diff end
      -- Never tostring() a timestamp: Lua formats numbers as %.14g, and a
      -- 16-digit microsecond value would lose its last digits -- roughly a
      -- 100us quantum that silently forgives debt at high rates. %.0f prints
      -- the integral double exactly.
      next_state[i] = string.format('%.0f', new_tat)
      next_ttl_ms[i] = math.ceil((new_tat - now) / 1000)
    end
  else
    local period, requests = p1, p2
    local start = now - (now % period)
    local count = 0
    if state then
      local sep = string.find(state, ':', 1, true)
      if sep then
        local s = tonumber(string.sub(state, 1, sep - 1))
        local c = tonumber(string.sub(state, sep + 1))
        if s == start and c then count = c end
      end
    end
    local left = requests - count
    if left < 0 then left = 0 end
    local boundary = start + period - now

    allowed[i] = cost <= left
    exceeds[i] = cost > requests
    remain_current[i] = left
    remain_charged[i] = left - cost
    reset_charged[i] = boundary
    if count == 0 then reset_current[i] = 0 else reset_current[i] = boundary end
    if allowed[i] or exceeds[i] then retry[i] = -1 else retry[i] = boundary end
    -- The same %.0f rule as for GCRA: every stored number prints as an exact
    -- integer, and no alignment assumption ever enters the serialization.
    next_state[i] = string.format('%.0f', start) .. ':' .. string.format('%.0f', count + cost)
    next_ttl_ms[i] = math.ceil(boundary / 1000)
  end

  if not shadow[i] and not allowed[i] then
    admitted = 0
  end
end

if admitted == 1 and mode == 'decide' then
  for i = 1, n do
    if allowed[i] and next_state[i] then
      redis.call('SET', KEYS[i], next_state[i], 'PX', next_ttl_ms[i])
    end
  end
end

local out = {admitted}
for i = 1, n do
  if admitted == 1 and mode == 'decide' and allowed[i] then
    out[#out + 1] = 1
    out[#out + 1] = 0
    out[#out + 1] = remain_charged[i]
    out[#out + 1] = -1
    out[#out + 1] = reset_charged[i]
  else
    out[#out + 1] = allowed[i] and 1 or 0
    out[#out + 1] = exceeds[i] and 1 or 0
    out[#out + 1] = remain_current[i]
    out[#out + 1] = retry[i]
    out[#out + 1] = reset_current[i]
  end
end
return out
