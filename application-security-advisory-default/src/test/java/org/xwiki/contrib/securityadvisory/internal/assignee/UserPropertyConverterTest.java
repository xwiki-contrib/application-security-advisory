/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.securityadvisory.internal.assignee;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;
import org.xwiki.user.UserReferenceSerializer;

import jakarta.inject.Named;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link UserPropertyConverter}.
 *
 * @version $Id$
 */
@ComponentTest
class UserPropertyConverterTest
{
    private static final DocumentReference HOLDER = new DocumentReference("xwiki", "Space", "Advisory");

    private static final DocumentReference USER_DOCUMENT = new DocumentReference("xwiki", "XWiki", "surli");

    @InjectMockComponents
    private UserPropertyConverter converter;

    @MockComponent
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @MockComponent
    @Named("compactwiki")
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @MockComponent
    @Named("document")
    private UserReferenceResolver<DocumentReference> userReferenceResolver;

    @MockComponent
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    @Test
    void resolve()
    {
        assertEquals(Optional.empty(), this.converter.resolve(null, HOLDER));
        assertEquals(Optional.empty(), this.converter.resolve(" ", HOLDER));

        UserReference user = mock(UserReference.class);
        when(this.documentReferenceResolver.resolve("XWiki.surli", HOLDER)).thenReturn(USER_DOCUMENT);
        when(this.userReferenceResolver.resolve(USER_DOCUMENT)).thenReturn(user);
        assertEquals(Optional.of(user), this.converter.resolve(" XWiki.surli ", HOLDER));
    }

    @Test
    void serialize()
    {
        UserReference user = mock(UserReference.class);
        when(this.userReferenceSerializer.serialize(user)).thenReturn(USER_DOCUMENT);
        when(this.entityReferenceSerializer.serialize(USER_DOCUMENT, HOLDER)).thenReturn("XWiki.surli");
        assertEquals("XWiki.surli", this.converter.serialize(user, HOLDER));

        // A user which is not backed by a document cannot be stored.
        assertNull(this.converter.serialize(mock(UserReference.class), HOLDER));
    }
}
