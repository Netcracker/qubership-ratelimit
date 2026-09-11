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

local call = redis.call
local fmt = string.format
local find = string.find
local sub = string.sub
local floor = math.floor
local ceil = math.ceil
local tonum = tonumber

local t = call('TIME')
local now = t[1] * 1000000 + t[2]

local decide = ARGV[1] == 'decide'
local cost = tonum(ARGV[2])
local n = #KEYS

local states = n > 0 and call('MGET', unpack(KEYS)) or {}

-- The first pass writes the uncharged shape of every reply quintuple straight
-- into out and keeps the charged shape as numbers on the side: rc/sc are the
-- charged remaining and reset, sa/sb the next state (sa alone for GCRA, both
-- for a fixed window), set only for buckets whose own verdict allows. The
-- commit pass patches the reply and serializes state in one place, so refused
-- decisions and peeks never pay for strings they would throw away.
local out = {1}
local rc, sc, sa, sb = {}, {}, {}, {}

local admitted = 1

for i = 1, n do
  local base = 2 + (i - 1) * 5
  local alg = tonum(ARGV[base + 1])
  local p1 = tonum(ARGV[base + 2])
  local p2 = tonum(ARGV[base + 3])
  local p3 = tonum(ARGV[base + 4])
  local shadow = ARGV[base + 5] == '1'
  local state = states[i]
  local o = 1 + (i - 1) * 5

  local allowed = false

  if alg == 1 then
    local emission, tau, burst = p1, p2, p3
    local tat = now
    if state then
      local stored = tonum(state)
      if stored and stored > now then tat = stored end
    end
    local depth = tat - now
    local current = floor((tau - depth) / emission)
    if current < 0 then current = 0 end

    local exceeds = false
    local retry = -1
    if cost > burst then
      exceeds = true
    else
      local new_tat = tat + emission * cost
      local diff = now - (new_tat - tau)
      if diff >= 0 then
        allowed = true
        rc[i] = floor(diff / emission)
        sc[i] = new_tat - now
        sa[i] = new_tat
      else
        retry = -diff
      end
    end
    out[o + 1] = allowed and 1 or 0
    out[o + 2] = exceeds and 1 or 0
    out[o + 3] = current
    out[o + 4] = retry
    out[o + 5] = depth
  else
    local period, requests = p1, p2
    local start = now - (now % period)
    local count = 0
    if state then
      local sep = find(state, ':', 1, true)
      if sep then
        local s = tonum(sub(state, 1, sep - 1))
        local c = tonum(sub(state, sep + 1))
        if s == start and c then count = c end
      end
    end
    local left = requests - count
    if left < 0 then left = 0 end
    local boundary = start + period - now

    allowed = cost <= left
    local exceeds = cost > requests
    if allowed then
      rc[i] = left - cost
      sc[i] = boundary
      sa[i] = start
      sb[i] = count + cost
    end
    out[o + 1] = allowed and 1 or 0
    out[o + 2] = exceeds and 1 or 0
    out[o + 3] = left
    out[o + 4] = (allowed or exceeds) and -1 or boundary
    out[o + 5] = count == 0 and 0 or boundary
  end

  if not shadow and not allowed then
    admitted = 0
  end
end

out[1] = admitted

if admitted == 1 and decide then
  for i = 1, n do
    if sa[i] then
      local o = 1 + (i - 1) * 5
      out[o + 1] = 1
      out[o + 2] = 0
      out[o + 3] = rc[i]
      out[o + 4] = -1
      out[o + 5] = sc[i]
      -- Never tostring() a timestamp: Lua formats numbers as %.14g, and a
      -- 16-digit microsecond value would lose its last digits -- roughly a
      -- 100us quantum that silently forgives debt at high rates. %.0f prints
      -- every stored number of either algorithm as an exact integer.
      local state
      if sb[i] then
        state = fmt('%.0f:%.0f', sa[i], sb[i])
      else
        state = fmt('%.0f', sa[i])
      end
      call('SET', KEYS[i], state, 'PX', ceil(sc[i] / 1000))
    end
  end
end

return out
