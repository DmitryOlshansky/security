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

import com.amazon.dlic.auth.ldap.LdapUser;
import org.ldaptive.AbstractLdapBean;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.SearchEntry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.OutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import org.elasticsearch.ElasticsearchException;

import com.amazon.opendistroforelasticsearch.security.user.User;
import com.google.common.io.BaseEncoding;

public class Base64Helper {

    private static final Set<Class<?>> SAFE_CLASSES = new HashSet<>(
        Arrays.asList(
            String.class,
            SocketAddress.class,
            InetSocketAddress.class,
            Pattern.class,
            User.class,
            SourceFieldsContext.class,
            LdapUser.class,
            SearchEntry.class,
            LdapEntry.class,
            AbstractLdapBean.class,
            LdapAttribute.class
        )
    );

    private static final List<Class<?>> SAFE_ASSIGNABLE_FROM_CLASSES = Arrays.asList(
        InetAddress.class,
        Number.class,
        Collection.class,
        Map.class,
        Enum.class,
        WildcardMatcher.class
    );

    private static final Set<String> SAFE_CLASS_NAMES = new HashSet<>(
        Arrays.asList(
            "org.ldaptive.LdapAttribute$LdapAttributeValues"
        )
    );

    private static boolean isSafeClass(Class cls) {
        return cls.isArray() ||
            SAFE_CLASSES.contains(cls) ||
            SAFE_CLASS_NAMES.contains(cls.getName()) ||
            SAFE_ASSIGNABLE_FROM_CLASSES.stream().anyMatch(c -> c.isAssignableFrom(cls));
    }

    private final static class SafeObjectOutputStream extends ObjectOutputStream {

        public SafeObjectOutputStream(OutputStream out) throws IOException {
            super(out);
            enableReplaceObject(true);
        }

        @Override
        protected Object replaceObject(Object obj) throws IOException {
            Class<?> clazz = obj.getClass();
            if (isSafeClass(clazz)) {
                return obj;
            }
            throw new IOException("Unauthorized serialization attempt " + clazz.getName());
        }
    }

    public static String serializeObject(final Serializable object) {

        if (object == null) {
            throw new IllegalArgumentException("object must not be null");
        }

        try {
            final ByteArrayOutputStream bos = new ByteArrayOutputStream();
            final ObjectOutputStream out = new SafeObjectOutputStream(bos);
            out.writeObject(object);
            final byte[] bytes = bos.toByteArray();
            return BaseEncoding.base64().encode(bytes);
        } catch (final Exception e) {
            throw new ElasticsearchException("Fail to serialize %s", object, e);
        }
    }

    public static Serializable deserializeObject(final String string) {

        if (string == null) {
            throw new IllegalArgumentException("string must not be null");
        }

        SafeObjectInputStream in = null;

        try {
            final byte[] userr = BaseEncoding.base64().decode(string);
            final ByteArrayInputStream bis = new ByteArrayInputStream(userr); //NOSONAR
            in = new SafeObjectInputStream(bis); //NOSONAR
            return (Serializable) in.readObject();
        } catch (final Exception e) {
            throw new ElasticsearchException(e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    private final static class SafeObjectInputStream extends ObjectInputStream {

        public SafeObjectInputStream(InputStream in) throws IOException {
            super(in);
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {

            Class<?> clazz = super.resolveClass(desc);
            if (isSafeClass(clazz)) {
                return clazz;
            }

            throw new InvalidClassException("Unauthorized deserialization attempt ", clazz.getName());
        }
    }
}
