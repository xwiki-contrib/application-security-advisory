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
package org.xwiki.contrib.securityadvisory.test.po;

import org.openqa.selenium.By;
import org.xwiki.test.ui.po.ViewPage;

/**
 * Represents the home page of the Security Advisory Application, listing the advisories.
 *
 * @version $Id$
 * @since 2.3
 */
public class SecurityAdvisoryHomePage extends ViewPage
{
    /**
     * Go to the home page of the application.
     *
     * @return the home page
     */
    public static SecurityAdvisoryHomePage gotoPage()
    {
        getUtil().gotoPage("SecurityAdvisoryApplication", "WebHome");
        return new SecurityAdvisoryHomePage();
    }

    /**
     * Click on the action to add a new advisory, which opens the edit form of a new advisory page.
     *
     * @return the edit form of the new advisory
     */
    public SecurityAdvisoryEditPage clickAddAdvisory()
    {
        getDriver().addPageNotYetReloadedMarker();
        getDriver().findElement(By.cssSelector("#actionBox a.action.add")).click();
        // The click goes through a page generating the name of the new advisory, which redirects to its edit form.
        getDriver().waitUntilPageIsReloaded();
        return new SecurityAdvisoryEditPage();
    }
}
