/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.support;

import java.io.Serializable;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.Iterator;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.base.Preconditions;

public abstract class WildcardMatcher implements Predicate<String>, Serializable {
    private static final long serialVersionUID = 7133340878814769890L;

    // TODO: make serializable, hashable etc.
    public static final WildcardMatcher ANY = new WildcardMatcher() {
        private static final long serialVersionUID = 7933900657569940488L;

        @Override
        public boolean matchAny(Stream<String> candidates) {
            return true;
        }

        @Override
        public boolean matchAny(Collection<String> candidates) {
            return true;
        }

        @Override
        public boolean matchAny(String[] candidates) {
            return true;
        }

        @Override
        public boolean matchAll(Stream<String> candidates) {
            return true;
        }

        @Override
        public boolean matchAll(Collection<String> candidates) {
            return true;
        }

        @Override
        public boolean matchAll(String[] candidates) {
            return true;
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(Stream<String> candidates, Collector<String, ?, T> collector) {
            return candidates.collect(collector);
        }

        @Override
        public boolean test(String candidate) {
            return true;
        }

        @Override
        public String toString() { return "*"; }
    };

    // TODO: make serializable, hashable etc.
    public static final WildcardMatcher NONE = new WildcardMatcher() {
        private static final long serialVersionUID = -7034434965452534578L;

        @Override
        public boolean matchAny(Stream<String> candidates) {
            return false;
        }

        @Override
        public boolean matchAny(Collection<String> candidates) {
            return false;
        }

        @Override
        public boolean matchAny(String[] candidates) {
            return false;
        }

        @Override
        public boolean matchAll(Stream<String> candidates) {
            return false;
        }

        @Override
        public boolean matchAll(Collection<String> candidates) {
            return false;
        }

        @Override
        public boolean matchAll(String[] candidates) {
            return false;
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(Stream<String> candidates, Collector<String, ?, T> collector) {
            return Stream.<String>empty().collect(collector);
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(Collection<String> candidate, Collector<String, ?, T> collector) {
            return Stream.<String>empty().collect(collector);
        }

        @Override
        public <T extends Collection<String>> T getMatchAny(String[] candidate, Collector<String, ?, T> collector) {
            return Stream.<String>empty().collect(collector);
        }

        @Override
        public boolean test(String candidate) {
            return false;
        }

        @Override
        public String toString() { return "<NONE>"; }
    };

    public static WildcardMatcher from(String pattern, boolean caseSensitive) {
        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            return new RegexMatcher(pattern, caseSensitive);
        } else if (pattern.indexOf('?') >= 0 || pattern.indexOf('*') >= 0) {
            return caseSensitive ?  new SimpleMatcher(pattern) : new CasefoldingMatcher(pattern,  SimpleMatcher::new);
        }
        else {
            return caseSensitive ? new Exact(pattern) : new CasefoldingMatcher(pattern, Exact::new);
        }
    }

    public static WildcardMatcher from(String pattern) {
        return from(pattern, true);
    }

    // This may in future use more optimized techniques to combine multiple WildcardMatchers in a single automaton
    public static WildcardMatcher from(Stream<String> patterns, boolean caseSensitive) {
        Collection<WildcardMatcher> matchers = patterns.map(p -> WildcardMatcher.from(p, caseSensitive)).collect(Collectors.toList());
        return matchers.isEmpty() ? NONE : new MatcherCombiner(matchers);
    }

    public static WildcardMatcher from(Collection<String> patterns, boolean caseSensitive) {
        return from(patterns == null ? Stream.empty() : patterns.stream(), caseSensitive);
    }

    public static WildcardMatcher from(String[] patterns, boolean caseSensitive) {
        return from(patterns == null ? Stream.empty() : Arrays.stream(patterns), caseSensitive);
    }

    public static WildcardMatcher from(Stream<String> patterns) {
        return from(patterns, true);
    }
    public static WildcardMatcher from(Collection<String> patterns) {
        return from(patterns, true);
    }

    public static WildcardMatcher from(String[] patterns) {
        return from(patterns, true);
    }

    public boolean matchAny(Stream<String> candidates) {
        return candidates.anyMatch(this);
    }

    public boolean matchAny(Collection<String> candidates) {
        return matchAny(candidates.stream());
    }

    public boolean matchAny(String[] candidates) {
        return matchAny(Arrays.stream(candidates));
    }

    public boolean matchAll(Stream<String> candidates) {
        return candidates.allMatch(this);
    }

    public boolean matchAll(Collection<String> candidates) {
        return matchAll(candidates.stream());
    }

    public boolean matchAll(String[] candidates) {
        return matchAll(Arrays.stream(candidates));
    }

    public <T extends Collection<String>> T getMatchAny(Stream<String> candidates, Collector<String, ?, T> collector) {
        return candidates.filter(this).collect(collector);
    }

    public <T extends Collection<String>> T getMatchAny(Collection<String> candidate, Collector<String, ?, T> collector) {
        return getMatchAny(candidate.stream(), collector);
    }

    public <T extends Collection<String>> T getMatchAny(final String[] candidate, Collector<String, ?, T> collector) {
        return getMatchAny(Arrays.stream(candidate), collector);
    }

    public Optional<WildcardMatcher> findFirst(final String candidate) {
        return Optional.empty();
    }

    public static List<WildcardMatcher> matchers(Collection<String> patterns) {
        return patterns.stream().map(p -> WildcardMatcher.from(p, true))
                .collect(Collectors.toList());
    }

    public static WildcardMatcher merge(Collection<WildcardMatcher> patterns) {
        return new MatcherCombiner(new ArrayList<>(patterns));
    }

    public static boolean allMatches(final Collection<WildcardMatcher> matchers, final Collection<String> candidate) {
        int matchedPatternNum = 0;
        for (WildcardMatcher matcher : matchers) {
            if (matcher.matchAny(candidate)) {
                matchedPatternNum++;
            }
        }
        return matchedPatternNum == matchers.size() && matchers.size() > 0;
    }

    public static List<String> getAllMatchingPatterns(final Collection<WildcardMatcher> matchers, final String candidate) {
        return matchers.stream().filter(p -> p.test(candidate)).map(Objects::toString).collect(Collectors.toList());
    }

    public static List<String> getAllMatchingPatterns(final Collection<WildcardMatcher> pattern, final Collection<String> candidates) {
        return pattern.stream().filter(p -> p.matchAny(candidates)).map(Objects::toString).collect(Collectors.toList());
    }

    /**
     *
     * @param set of string to modify
     * @param matcher WildcardMatcher matcher to use to filter
     * @return
     */
    public static boolean WildcardMatcherRetainInSet(Set<String> set, WildcardMatcher matcher) {
        if(set == null || set.isEmpty()) {
            return false;
        }
        
        boolean modified = false;
        Iterator<String> it = set.iterator();
        while(it.hasNext()) {
            String v = it.next();
            if(!matcher.test(v)) {
                it.remove();
                modified = true;
            }
        }
        return modified;
    }


    //
    // --- Implementation specializations ---
    //
    // Casefolding matcher - sits on top of case-sensitive matcher 
    // and proxies toLower() of input string to the wrapped matcher
    private static final class CasefoldingMatcher extends WildcardMatcher {
        static final long serialVersionUID = -5651976925009922927L;

        private final WildcardMatcher inner;

        public CasefoldingMatcher(String pattern, Function<String, WildcardMatcher> simpleWildcardMatcher) {
            this.inner = simpleWildcardMatcher.apply(pattern.toLowerCase());
        }

        @Override
        public boolean test(String candidate) {
            return inner.test(candidate.toLowerCase());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            CasefoldingMatcher that = (CasefoldingMatcher) o;
            return inner.equals(that.inner);
        }

        @Override
        public int hashCode() {
            return inner.hashCode();
        }

        @Override
        public String toString() {
            return inner.toString();
        }
    }

    public static final class Exact extends WildcardMatcher {
        private static final long serialVersionUID = -1065006818437830497L;

        private final String pattern;

        private Exact(String pattern) {
            this.pattern = pattern;
        }

        @Override
        public boolean test(String candidate) {
            return pattern.equals(candidate);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Exact that = (Exact) o;
            return pattern.equals(that.pattern);
        }

        @Override
        public int hashCode() {
            return pattern.hashCode();
        }

        @Override
        public String toString() {
            return pattern;
        }
    }

    // RegexMatcher uses JDK Pattern to test for matching,
    // assumes "/<regex>/" strings as input pattern
    private static final class RegexMatcher extends WildcardMatcher {
        private static final long serialVersionUID = 5655822039969887331L;

        private final Pattern pattern;

        private RegexMatcher(String pattern, boolean caseSensitive) {
            Preconditions.checkArgument(pattern.length() > 1 && pattern.startsWith("/") && pattern.endsWith("/"));
            final String stripSlashesPattern = pattern.substring(1, pattern.length() - 1);
            this.pattern = caseSensitive ? Pattern.compile(stripSlashesPattern) : Pattern.compile(stripSlashesPattern, Pattern.CASE_INSENSITIVE);
        }

        @Override
        public boolean test(String candidate) {
            return pattern.matcher(candidate).matches();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RegexMatcher that = (RegexMatcher) o;
            return pattern.pattern().equals(that.pattern.pattern());
        }

        @Override
        public int hashCode() {
            return pattern.pattern().hashCode();
        }

        @Override
        public String toString(){ return "/" + pattern.pattern() + "/"; }
    }

    // Simple implementation of WildcardMatcher matcher with * and ? without
    // using exlicit stack or recursion (as long as we don't need sub-matches it does work)
    // allows us to save on resources and heap allocations unless Regex is required
    private static final class SimpleMatcher extends WildcardMatcher {
        private static final long serialVersionUID = 5917562223849696115L;

        private final String pattern;

        SimpleMatcher(String pattern) {
            this.pattern = pattern;
        }

        @Override
        public boolean test(String candidate) {
            int i = 0;
            int j = 0;
            int n = candidate.length();
            int m = pattern.length();
            int text_backup = -1;
            int wild_backup = -1;
            while (i < n) {
                if (j < m && pattern.charAt(j) == '*') {
                    text_backup = i;
                    wild_backup = ++j;
                } else if (j < m && (pattern.charAt(j) == '?' || pattern.charAt(j) == candidate.charAt(i))) {
                    i++;
                    j++;
                } else {
                    if (wild_backup == -1) return false;
                    i = ++text_backup;
                    j = wild_backup;
                }
            }
            while (j < m && pattern.charAt(j) == '*') j++;
            return j >= m;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SimpleMatcher that = (SimpleMatcher) o;
            return pattern.equals(that.pattern);
        }

        @Override
        public int hashCode() {
            return pattern.hashCode();
        }

        @Override
        public String toString(){ return pattern; }
    }

    // MatcherCombiner is a combination of a set of matchers
    // matches if any of the set do
    // Empty MultiMatcher always returns false
    private static final class MatcherCombiner extends WildcardMatcher {
        private static final long serialVersionUID = 7493891439965468040L;

        private final Collection<WildcardMatcher> wildcardMatchers;

        MatcherCombiner(Collection<WildcardMatcher> wildcardMatchers) {
            this.wildcardMatchers = wildcardMatchers;
        }

        @Override
        public boolean test(String candidate) {
            return wildcardMatchers.stream().anyMatch(m -> m.test(candidate));
        }

        @Override
        public Optional<WildcardMatcher> findFirst(final String candidate) {
            return wildcardMatchers.stream().filter(m -> m.test(candidate)).findFirst();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            MatcherCombiner that = (MatcherCombiner) o;
            return wildcardMatchers.equals(that.wildcardMatchers);
        }

        @Override
        public int hashCode() {
            return wildcardMatchers.hashCode();
        }

        @Override
        public String toString() { return wildcardMatchers.toString(); }
    }
}
