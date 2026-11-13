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
import org.xwiki.livedata.test.po.LiveDataElement;
import org.xwiki.livedata.test.po.TableLayoutElement;
import org.xwiki.test.ui.po.SuggestInputElement;
import org.xwiki.test.ui.po.ViewPage;
import org.xwiki.test.ui.po.editor.RightsEditPage;

/**
 * Represents the home page of the Security Advisory Application, listing the advisories.
 *
 * @version $Id$
 * @since 2.3
 */
public class SecurityAdvisoryHomePage extends ViewPage
{
    private static final By SECURITY_ENTRIES_ACCESS_WARNING_LINK = By.cssSelector("#xwikicontent .warningmessage a");

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
     * @return the live data listing the advisories, once loaded
     */
    public LiveDataElement getAdvisories()
    {
        LiveDataElement liveData = new LiveDataElement("securityadvisoryapplication");
        liveData.waitUntilReady();
        return liveData;
    }

    /**
     * Remove the filter of a column of the advisories, the way a user does it: by removing the selected value of the
     * column filter, which needs to be a list filter. The advisories are then fetched again, without that filter.
     *
     * @param columnLabel the label of the column to stop filtering
     */
    public void removeAdvisoriesColumnFilter(String columnLabel)
    {
        TableLayoutElement tableLayout = getAdvisories().getTableLayout();
        new SuggestInputElement(tableLayout.getFilter(columnLabel)).clearSelectedSuggestions();
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

    /**
     * @return {@code true} if the page warns that the space holding the advisories is open to all users
     */
    public boolean hasSecurityEntriesAccessWarning()
    {
        return getDriver().hasElementWithoutWaiting(SECURITY_ENTRIES_ACCESS_WARNING_LINK);
    }

    /**
     * Click on the link of the warning about the space holding the advisories being open to all users.
     *
     * @return the rights editor of the space holding the advisories, where its access can be restricted
     */
    public RightsEditPage clickSecurityEntriesAccessWarningLink()
    {
        getDriver().addPageNotYetReloadedMarker();
        getDriver().findElement(SECURITY_ENTRIES_ACCESS_WARNING_LINK).click();
        getDriver().waitUntilPageIsReloaded();
        return new RightsEditPage();
    }
}
