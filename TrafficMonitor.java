import java.util.HashMap;
import java.util.Map;

public class TrafficMonitor {
    private static Map<String, Integer> ipRequestCount = new HashMap<>();
    private static Map<String, Long> lastRequestTime = new HashMap<>();
    private static final int MAX_REQUESTS_PER_MIN = 10;

    public static synchronized boolean isSuspicious(String ip) {
        long now = System.currentTimeMillis();

        if (lastRequestTime.containsKey(ip) && (now - lastRequestTime.get(ip) > 60_000)) {
            ipRequestCount.put(ip, 0);
        }

        ipRequestCount.put(ip, ipRequestCount.getOrDefault(ip, 0) + 1);
        lastRequestTime.put(ip, now);

        return ipRequestCount.get(ip) > MAX_REQUESTS_PER_MIN;
    }
}

