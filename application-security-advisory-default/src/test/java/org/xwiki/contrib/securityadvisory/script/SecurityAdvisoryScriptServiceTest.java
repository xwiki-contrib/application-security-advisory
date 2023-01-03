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
package org.xwiki.contrib.securityadvisory.script;

import org.junit.jupiter.api.Test;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.internal.VersionReleasedManager;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ComponentTest
class SecurityAdvisoryScriptServiceTest
{
    @InjectMockComponents
    private SecurityAdvisoryScriptService scriptService;

    @MockComponent
    private VersionReleasedManager versionReleasedManager;

    @Test
    void isReleased() throws SecurityAdvisoryException
    {
        String product = "test";
        String version = "4.2.3";
        when(this.versionReleasedManager.isVersionReleased(product, version)).thenReturn(true);
        assertTrue(this.scriptService.isReleased(product, version));
        verify(this.versionReleasedManager).isVersionReleased(product, version);
    }

    @Test
    void isSingleVersion()
    {
        assertTrue(this.scriptService.isSingleVersion("1.2"));
        assertTrue(this.scriptService.isSingleVersion("1"));
        assertTrue(this.scriptService.isSingleVersion("1.54.3"));
        assertTrue(this.scriptService.isSingleVersion("1.21"));
        assertTrue(this.scriptService.isSingleVersion("1.43.3.21"));
        assertFalse(this.scriptService.isSingleVersion("<1.21"));
        assertFalse(this.scriptService.isSingleVersion(">1.21"));
        assertFalse(this.scriptService.isSingleVersion("[1.2-1.3]"));
        assertFalse(this.scriptService.isSingleVersion("test"));
        assertTrue(this.scriptService.isSingleVersion("12.21-rc-1"));
        assertFalse(this.scriptService.isSingleVersion("12.21-RC-1"));
        assertTrue(this.scriptService.isSingleVersion("12.21-rc-42"));
        assertTrue(this.scriptService.isSingleVersion("12.21.23.43-milestone-3"));
        assertFalse(this.scriptService.isSingleVersion("12.21-rc-42.43"));
        assertFalse(this.scriptService.isSingleVersion("-milestone-42"));
    }
}