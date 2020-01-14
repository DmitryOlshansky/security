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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.Stack;
import java.util.regex.Pattern;

public class WildcardMatcher {

    private static final int NOT_FOUND = -1;

    /**
     * returns true if at least one candidate match at least one pattern (case sensitive)
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAny(final String[] pattern, final String[] candidate) {

        return matchAny(pattern, candidate, false);
    }
    
    public static boolean matchAny(final Collection<String> pattern, final Collection<String> candidate) {

        return matchAny(pattern, candidate, false);
    }

    /**
     * returns true if at least one candidate match at least one pattern
     *
     * @param pattern
     * @param candidate
     * @param ignoreCase
     * @return
     */
    public static boolean matchAny(final String[] pattern, final String[] candidate, boolean ignoreCase) {

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (matchAny(string, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    /**
     * returns true if at least one candidate match at least one pattern
     *
     * @param pattern
     * @param candidate
     * @param ignoreCase
     * @return
     */
    public static boolean matchAny(final Collection<String> pattern, final String[] candidate, boolean ignoreCase) {

        for (String string: pattern) {
            if (matchAny(string, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }
    
    public static boolean matchAny(final Collection<String> pattern, final Collection<String> candidate, boolean ignoreCase) {

        for (String string: pattern) {
            if (matchAny(string, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    /**
     * return true if all candidates find a matching pattern
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAll(final String[] pattern, final String[] candidate) {


        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (!matchAny(pattern, string)) {
                return false;
            }
        }

        return true;
    }

    /**
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean allPatternsMatched(final String[] pattern, final String[] candidate) {

        int matchedPatternNum = 0;

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (matchAny(string, candidate)) {
                matchedPatternNum++;
            }
        }

        return matchedPatternNum == pattern.length && pattern.length > 0;
    }

    public static boolean allPatternsMatched(final Collection<String> pattern, final Collection<String> candidate) {

        int matchedPatternNum = 0;

        for (String string:pattern) {
            if (matchAny(string, candidate)) {
                matchedPatternNum++;
            }
        }

        return matchedPatternNum == pattern.size() && pattern.size() > 0;
    }

    public static boolean matchAny(final String pattern, final String[] candidate) {
        return matchAny(pattern, candidate, false);
    }
    
    public static boolean matchAny(final String pattern, final Collection<String> candidate) {
        return matchAny(pattern, candidate, false);
    }

    /**
     * return true if at least one candidate matches the given pattern
     *
     * @param pattern
     * @param candidate
     * @param ignoreCase
     * @return
     */
    public static boolean matchAny(final String pattern, final String[] candidate, boolean ignoreCase) {

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (match(pattern, string, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    public static boolean matchAny(final String pattern, final Collection<String> candidates, boolean ignoreCase) {

        for (String candidate: candidates) {
            if (match(pattern, candidate, ignoreCase)) {
                return true;
            }
        }

        return false;
    }

    public static String[] matches(final String pattern, final String[] candidate, boolean ignoreCase) {

        final List<String> ret = new ArrayList<String>(candidate.length);
        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (match(pattern, string, ignoreCase)) {
                ret.add(string);
            }
        }

        return ret.toArray(new String[0]);
    }

    public static List<String> getMatchAny(final String pattern, final String[] candidate) {

        final List<String> matches = new ArrayList<String>(candidate.length);

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (match(pattern, string)) {
                matches.add(string);
            }
        }

        return matches;
    }

    public static List<String> getMatchAny(final String[] patterns, final String[] candidate) {

        final List<String> matches = new ArrayList<String>(candidate.length);

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (matchAny(patterns, string)) {
                matches.add(string);
            }
        }

        return matches;
    }


    public static List<String> getMatchAny(final Collection<String> patterns, final String[] candidate) {

        final List<String> matches = new ArrayList<String>(candidate.length);

        for (int i = 0; i < candidate.length; i++) {
            final String string = candidate[i];
            if (matchAny(patterns, string)) {
                matches.add(string);
            }
        }

        return matches;
    }

    public static List<String> getMatchAny(final Collection<String> patterns, Collection<String> candidates) {

        final List<String> matches = new ArrayList<String>(candidates.size());

        for (String string: candidates) {
            if (matchAny(patterns, string)) {
                matches.add(string);
            }
        }

        return matches;
    }

    public static List<String> getMatchAny(final String pattern, final Collection<String> candidate) {

        final List<String> matches = new ArrayList<String>(candidate.size());

        for (final String string: candidate) {
            if (match(pattern, string)) {
                matches.add(string);
            }
        }

        return matches;
    }

    public static List<String> getMatchAny(final String[] patterns, final Collection<String> candidate) {

        final List<String> matches = new ArrayList<String>(candidate.size());

        for (final String string: candidate) {
            if (matchAny(patterns, string)) {
                matches.add(string);
            }
        }

        return matches;
    }
    
    public static Optional<String> getFirstMatchingPattern(final Collection<String> pattern, final String candidate) {

        for (String p : pattern) {
            if (match(p, candidate)) {
                return Optional.of(p);
            }
        }

        return Optional.empty();
    }


    public static List<String> getAllMatchingPatterns(final Collection<String> pattern, final String candidate) {

        final List<String> matches = new ArrayList<String>(pattern.size());

        for (String p : pattern) {
            if (match(p, candidate)) {
                matches.add(p);
            }
        }

        return matches;
    }

    public static List<String> getAllMatchingPatterns(final Collection<String> pattern, final Collection<String> candidates) {

        final List<String> matches = new ArrayList<String>(pattern.size());

        for (String c : candidates) {
            matches.addAll(getAllMatchingPatterns(pattern, c));
        }

        return matches;
    }


    /**
     * returns true if the candidate matches at least one pattern
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAny(final String pattern[], final String candidate) {

        for (int i = 0; i < pattern.length; i++) {
            final String string = pattern[i];
            if (match(string, candidate)) {
                return true;
            }
        }

        return false;
    }

    /**
     * returns true if the candidate matches at least one pattern
     *
     * @param pattern
     * @param candidate
     * @return
     */
    public static boolean matchAny(final Collection<String> pattern, final String candidate) {

        for (String string: pattern) {
            if (match(string, candidate)) {
                return true;
            }
        }

        return false;
    }

    public static boolean match(final String pattern, final String candidate) {
        return match(pattern, candidate, false);
    }

    public static boolean match(String pattern, String candidate, boolean ignoreCase) {

        if (pattern == null || candidate == null) {
            return false;
        }

        if(ignoreCase) {
            pattern = pattern.toLowerCase();
            candidate = candidate.toLowerCase();
        }

        if (pattern.startsWith("/") && pattern.endsWith("/")) {
            // regex
            return Pattern.matches("^"+pattern.substring(1, pattern.length() - 1)+"$", candidate);
        } else if (pattern.length() == 1 && pattern.charAt(0) == '*') {
            return true;
        } else if (pattern.indexOf('?') == NOT_FOUND && pattern.indexOf('*') == NOT_FOUND) {
            return pattern.equals(candidate);
        } else {
            return simpleWildcardMatch(pattern, candidate);
        }
    }

    public static boolean containsWildcard(final String pattern) {
        if (pattern != null
                && (pattern.indexOf("*") > NOT_FOUND || pattern.indexOf("?") > NOT_FOUND || (pattern.startsWith("/") && pattern
                        .endsWith("/")))) {
            return true;
        }

        return false;
    }

    /**
     *
     * @param set will be modified
     * @param stringContainingWc
     * @return
     */
    public static boolean wildcardRemoveFromSet(Set<String> set, String stringContainingWc) {
        if(set == null || set.isEmpty()) {
            return false;
        }
        if(!containsWildcard(stringContainingWc) && set.contains(stringContainingWc)) {
            return set.remove(stringContainingWc);
        } else {
            boolean modified = false;
            Set<String> copy = new HashSet<>(set);

            for(String it: copy) {
                if(WildcardMatcher.match(stringContainingWc, it)) {
                    modified = set.remove(it) || modified;
                }
            }
            return modified;
        }
    }

    /**
     *
     * @param set will be modified
     * @param stringContainingWc
     * @return
     */
    public static boolean wildcardRetainInSet(Set<String> set, String[] setContainingWc) {
        if(set == null || set.isEmpty()) {
            return false;
        }
        boolean modified = false;
        Set<String> copy = new HashSet<>(set);

        for(String it: copy) {
            if(!WildcardMatcher.matchAny(setContainingWc, it)) {
                modified = set.remove(it) || modified;
            }
        }
        return modified;
    }

    private static boolean simpleWildcardMatch(final String pattern, final String candidate) {
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
}
