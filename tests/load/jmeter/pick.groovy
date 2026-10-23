// Schedules the next request of this thread and picks its user, group, and
// operation. Both thread groups of ratelimit-load.jmx run this script. It
// sets the variables the plan reads: wait (milliseconds until the request is
// due), lag (how late the thread claimed it), op (READ, LIST, SEARCH, or STOP
// once the schedule is over), user, token, group, item, and kind.
//
// Each thread group shares one arrival schedule among its threads: Poisson
// arrivals at the rate of each step of the steps property (hotSteps for the
// hot users), given as rate:seconds pairs. A thread claims the next arrival
// and waits for it, so the rate does not depend on response times while a
// free thread is left; once every thread is busy, arrivals fall behind and
// lag grows.
//
// The tokens file (the tokens property) is read on the first request and
// read again once it changes, checked at most every five seconds, so the
// tokens that loadkit tokens -watch renews take effect.
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicLong

def random = ThreadLocalRandom.current()
def hotGroup = ctx.getThreadGroup().getName() == 'hot users'
def clockKey = hotGroup ? 'loadtest.clock.hot' : 'loadtest.clock.background'

def clock = props.get(clockKey)
if (clock == null) {
    synchronized (props) {
        clock = props.get(clockKey)
        if (clock == null) {
            long end = 0
            def steps = props.getProperty(hotGroup ? 'hotSteps' : 'steps', '').split(',').findAll { it.trim() }.collect {
                def (rate, seconds) = it.trim().split(':')
                end += (seconds as long) * 1000000L
                [end: end, rate: rate as double]
            }
            // Every generator of a run starts its schedule at the moment the
            // start property names, so their steps line up; without it, now.
            long start = (props.getProperty('start', '0') as long) ?: System.currentTimeMillis()
            clock = [start: start, steps: steps, next: new AtomicLong()]
            props.put(clockKey, clock)
        }
    }
}

// The next arrival after prev, in microseconds since the start, or -1 once
// the schedule is over. A step with rate 0 sends nothing; an arrival drawn
// past the end of its step is redrawn in the next one, which keeps the
// arrivals of a piecewise constant rate a Poisson process.
def advance = { long prev ->
    long t = prev
    for (s in clock.steps) {
        if (t >= s.end) continue
        if (s.rate <= 0) { t = s.end; continue }
        long gap = (long) (-Math.log(1.0d - random.nextDouble()) / s.rate * 1000000d)
        if (t + gap < s.end) return t + gap
        t = s.end
    }
    return -1L
}
long arrival
while (true) {
    long prev = clock.next.get()
    arrival = advance(prev)
    if (arrival < 0 || clock.next.compareAndSet(prev, arrival)) break
}
if (arrival < 0) {
    vars.put('op', 'STOP')
    vars.put('wait', '0')
    return
}
long due = clock.start + arrival.intdiv(1000)
long now = System.currentTimeMillis()
vars.put('wait', String.valueOf(Math.max(0L, due - now)))
vars.put('lag', String.valueOf(Math.max(0L, now - due)))

long checkedAt = System.currentTimeMillis()
def st = props.get('loadtest.tokens')
if (st == null || checkedAt - st.checked.get() > 5000) {
    synchronized (props) {
        st = props.get('loadtest.tokens')
        if (st == null || checkedAt - st.checked.get() > 5000) {
            def file = new File(props.getProperty('tokens', 'tokens.csv'))
            long modified = file.lastModified()
            if (st == null || modified != st.modified) {
                def users = [], tokens = []
                int hot = 0
                file.eachLine('UTF-8') { line, n ->
                    if (n == 1 || line.isEmpty()) return
                    def f = line.split(',', 3)
                    users << f[0]
                    tokens << f[2]
                    if (f[1] == '1') hot++
                }
                if (users.isEmpty()) throw new IllegalStateException("${file} holds no tokens")
                def mix = props.getProperty('mix', '60,30,10').split(',').collect { it.trim() as int }
                st = [modified: modified, checked: new AtomicLong(checkedAt), next: st?.next ?: new AtomicLong(),
                      users: users as String[], tokens: tokens as String[], hot: hot,
                      groups: props.getProperty('groups', 'customers,orders,incidents,billing,products').split(','),
                      mix: mix, mixTotal: mix.sum()]
                props.put('loadtest.tokens', st)
            } else {
                st.checked.set(checkedAt)
            }
        }
    }
}

int i
String group
if (hotGroup) {
    if (st.hot == 0) throw new IllegalStateException('the hot users thread group runs, but the tokens file marks no user as hot')
    i = (int) (st.next.getAndIncrement() % st.hot)
    group = st.groups[i % st.groups.length]
    vars.put('kind', 'hot')
} else {
    int others = st.users.length - st.hot
    if (others == 0) throw new IllegalStateException('every user of the tokens file is hot, so the background thread group has none to pick')
    i = st.hot + random.nextInt(others)
    group = st.groups[random.nextInt(st.groups.length)]
    vars.put('kind', 'background')
}
int p = random.nextInt(st.mixTotal)
vars.put('op', p < st.mix[0] ? 'READ' : p < st.mix[0] + st.mix[1] ? 'LIST' : 'SEARCH')
vars.put('user', st.users[i])
vars.put('token', st.tokens[i])
vars.put('group', group)
vars.put('item', String.valueOf(random.nextInt(1000000)))
