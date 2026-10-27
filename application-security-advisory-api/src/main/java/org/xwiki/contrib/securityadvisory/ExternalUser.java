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
package org.xwiki.contrib.securityadvisory;

/**
 * Represents a user of the external system an advisory is imported from (e.g. a GitHub account), which can be mapped
 * to an XWiki user.
 *
 * @param hint the hint of the external system the user belongs to (e.g. {@code github}), so that users of
 *     different systems with the same identifier are never mixed up
 * @param id the stable identifier of the user in the external system (e.g. the numeric GitHub user id), which does
 *     not change when the user renames their account
 * @param login the login of the user in the external system, only used for display since it can change
 *
 * @version $Id$
 * @since 2.2.2
 */
public record ExternalUser(String hint, String id, String login)
{
}
