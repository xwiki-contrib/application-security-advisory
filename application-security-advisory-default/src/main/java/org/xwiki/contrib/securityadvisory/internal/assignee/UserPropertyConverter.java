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

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;
import org.xwiki.user.UserReferenceSerializer;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Converts the value of a users xproperty to a {@link UserReference} and back. The value is stored relatively to the
 * document holding the xproperty, as the users xproperty displayer does.
 *
 * @version $Id$
 * @since 2.2.2
 */
@Component(roles = UserPropertyConverter.class)
@Singleton
public class UserPropertyConverter
{
    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    @Named("compactwiki")
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    @Named("document")
    private UserReferenceResolver<DocumentReference> userReferenceResolver;

    @Inject
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    /**
     * @param value the value of the users xproperty
     * @param holderReference the reference of the document holding the xproperty
     * @return the user stored in the xproperty, or {@link Optional#empty()} if the xproperty is empty
     */
    public Optional<UserReference> resolve(String value, EntityReference holderReference)
    {
        Optional<UserReference> result = Optional.empty();
        if (StringUtils.isNotBlank(value)) {
            DocumentReference userDocumentReference =
                this.documentReferenceResolver.resolve(value.trim(), holderReference);
            result = Optional.of(this.userReferenceResolver.resolve(userDocumentReference));
        }
        return result;
    }

    /**
     * @param userReference the user to store in a users xproperty
     * @param holderReference the reference of the document holding the xproperty
     * @return the value to store in the xproperty, or {@code null} if the user is not backed by a document (e.g. the
     *     guest user)
     */
    public String serialize(UserReference userReference, EntityReference holderReference)
    {
        DocumentReference userDocumentReference = this.userReferenceSerializer.serialize(userReference);
        return (userDocumentReference != null)
            ? this.entityReferenceSerializer.serialize(userDocumentReference, holderReference) : null;
    }
}
