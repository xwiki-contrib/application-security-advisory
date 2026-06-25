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
package org.xwiki.contrib.securityadvisory.internal.github;

import java.util.List;

import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.objects.meta.PasswordMetaClass;

import jakarta.inject.Named;
import jakarta.inject.Singleton;

/**
 * Initializer for the xclass holding Github token information.
 *
 * @version $Id$
 * @since 2.1
 */
@Component
@Singleton
@Named("GithubTokenClassMandatoryDocumentInitializer")
public class GithubTokenClassMandatoryDocumentInitializer extends AbstractMandatoryClassInitializer
{
    /**
     * Authentication token.
     */
    public static final String TOKEN = "token";

    /**
     * Organization bound to the token.
     */
    public static final String ORGA  = "orga";

    /**
     * Reference of the xclass.
     */
    public static final EntityReference CLASS_REFERENCE =
        new LocalDocumentReference(List.of("SecurityAdvisoryApplication", "Code"), "GithubTokenClass");

    /**
     * Default constructor.
     */
    public GithubTokenClassMandatoryDocumentInitializer()
    {
        super(CLASS_REFERENCE);
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        xclass.addTextField(ORGA, ORGA, 255);
        xclass.addPasswordField(TOKEN, TOKEN, 255, PasswordMetaClass.CLEAR);
    }
}
