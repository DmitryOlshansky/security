package com.amazon.opendistroforelasticsearch.security.support.wildcard;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

// Case-sensitivity and other options are defined by concrete Wildcard implementation
public interface Wildcard {
    boolean matches(String candidate);

    default boolean matchesAny(Collection<String> candidates) {
        return candidates.stream().anyMatch(this::matches);
    }

    Wildcard ANY = candidate -> true;

    Wildcard NONE = candidate -> false;

    // This may in future use more optimized techniques to combine multiple wildcards in a single automaton
    static Wildcard caseSensitiveAny(Collection<String> patterns) {
        return patterns.isEmpty() ? Wildcard.NONE : new MultiWildcard(patterns.stream().map(Wildcard::caseSensitive).collect(Collectors.toList()));
    }

    static Wildcard caseInsensitiveAny(Collection<String> patterns) {
        return patterns.isEmpty() ? Wildcard.NONE : new MultiWildcard(patterns.stream().map(Wildcard::caseInsensitive).collect(Collectors.toList()));
    }

    static Wildcard caseSensitive(String pattern) {
        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            return new RegexWildcard(pattern, false);
        } else if (pattern.indexOf('?') >= 0 || pattern.indexOf('*') >= 0) {
            return new SimpleWildcard(pattern);
        }
        else {
            return new ExactMatchWildcard(pattern);
        }
    }

    static Wildcard caseInsensitive(String pattern) {
        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            return new RegexWildcard(pattern, false);
        } else if (pattern.indexOf('?') >= 0 || pattern.indexOf('*') >= 0) {
            return new CasefoldingWildcard(pattern, SimpleWildcard::new);
        }
        else {
            return new CasefoldingWildcard(pattern, ExactMatchWildcard::new);
        }
    }
}
