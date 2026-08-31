package com.aidocqa.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Slf4j
@Component
@RequiredArgsConstructor
public class SessionAuthGlobalFilter implements GlobalFilter, Ordered {

    private final ReactiveStringRedisTemplate redisTemplate;
    private static final String REDIS_SESSION_PREFIX = "session:";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Allow public authentication endpoints, swagger, and actuator without strict session checks
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        // 2. Extract Session ID from Authorization Header, X-Session-Token, or Cookie
        String sessionId = extractSessionId(request);

        if (sessionId == null || sessionId.isBlank()) {
            // Forward request downstream with existing headers; downstream services enforce their security
            return chain.filter(exchange);
        }

        // 3. Check Redis for fast session sliding window extension and identity propagation
        String redisKey = REDIS_SESSION_PREFIX + sessionId;

        return redisTemplate.opsForValue().get(redisKey)
                .flatMap(userId -> {
                    // Slide 10-minute session TTL in Redis
                    return redisTemplate.expire(redisKey, Duration.ofMinutes(10))
                            .then(Mono.zip(
                                    redisTemplate.opsForValue().get(redisKey + ":email").defaultIfEmpty(""),
                                    redisTemplate.opsForValue().get(redisKey + ":name").defaultIfEmpty(""),
                                    redisTemplate.opsForValue().get(redisKey + ":role").defaultIfEmpty("")
                            ).flatMap(tuple -> {
                                String email = tuple.getT1();
                                String name = tuple.getT2();
                                String role = tuple.getT3();

                                ServerHttpRequest.Builder builder = request.mutate()
                                        .header("X-User-Id", userId)
                                        .header("X-Session-Id", sessionId);

                                if (!email.isBlank()) {
                                    builder.header("X-User-Email", email);
                                }
                                if (!name.isBlank()) {
                                    builder.header("X-User-Name", name);
                                }
                                if (!role.isBlank()) {
                                    builder.header("X-User-Role", role);
                                }

                                ServerHttpRequest mutatedRequest = builder.build();
                                return chain.filter(exchange.mutate().request(mutatedRequest).build());
                            }));
                })
                .switchIfEmpty(Mono.defer(() -> {
                    // In case Redis is empty/offline, forward session header for DB verification
                    ServerHttpRequest mutatedRequest = request.mutate()
                            .header("X-Session-Id", sessionId)
                            .build();
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                }))
                .onErrorResume(e -> {
                    log.warn("Gateway Redis session verification bypassed: {}", e.getMessage());
                    return chain.filter(exchange);
                });
    }

    private boolean isPublicPath(String path) {
        return path.startsWith("/api/auth/")
                || path.startsWith("/api-docs")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/actuator");
    }

    private String extractSessionId(ServerHttpRequest request) {
        HttpHeaders headers = request.getHeaders();

        // 1. Authorization: Bearer <sessionId>
        String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7).trim();
        }

        // 2. X-Session-Token
        String sessionHeader = headers.getFirst("X-Session-Token");
        if (sessionHeader != null && !sessionHeader.isBlank()) {
            return sessionHeader.trim();
        }

        String sessionIdHeader = headers.getFirst("X-Session-Id");
        if (sessionIdHeader != null && !sessionIdHeader.isBlank()) {
            return sessionIdHeader.trim();
        }

        // 3. Cookie AIDOC_SESSION
        HttpCookie cookie = request.getCookies().getFirst("AIDOC_SESSION");
        if (cookie != null) {
            return cookie.getValue();
        }

        return null;
    }

    @Override
    public int getOrder() {
        return -100; // High priority before standard routing filters
    }
}
