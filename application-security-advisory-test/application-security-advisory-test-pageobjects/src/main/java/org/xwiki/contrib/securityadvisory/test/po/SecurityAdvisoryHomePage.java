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

import java.util.List;
import java.util.Map;

import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
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

    private static final String IMPACTED_PACKAGES_COLUMN = "Impacted packages";

    private static final String PATCHED_VERSIONS_COLUMN = "Patched versions";

    private static final By VERSION_BADGES = By.className("label");

    /**
     * A package impacted by an advisory, as displayed in the impacted packages column of the advisories.
     *
     * @param packageId the identifier of the package, for example {@code org.xwiki.platform:xwiki-platform-oldcore}
     * @param affectedRanges the ranges of the affected versions of the package, for example {@code [1.0,15.10.11)}
     * @param patchedVersions the versions of the package fixing the advisory, for example {@code 15.10.11}
     * @since 2.3.1
     */
    public record ImpactedPackage(String packageId, List<String> affectedRanges, List<String> patchedVersions)
    {
    }

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
     * Filter the advisories on one of their impacted packages, picked among the suggested packages. The advisories are
     * then fetched again, with that filter.
     *
     * @param packageId the identifier of the impacted package
     * @since 2.3.1
     */
    public void filterAdvisoriesByPackage(String packageId)
    {
        getAdvisories().getTableLayout().filterColumn(IMPACTED_PACKAGES_COLUMN, packageId, true,
            Map.of(TableLayoutElement.FILTER_COLUMN_SELECTIZE_WAIT_FOR_SUGGESTIONS, true));
    }

    /**
     * @param rowNumber the number of the row of the advisory, starting at 1
     * @return the packages impacted by the advisory, in the order of the impacted packages column, each with its
     *     affected version ranges and its patched versions
     * @since 2.3.1
     */
    public List<ImpactedPackage> getImpactedPackages(int rowNumber)
    {
        return getAdvisories().getTableLayout().getCell(IMPACTED_PACKAGES_COLUMN, rowNumber)
            .findElements(By.className("impacted-package")).stream()
            .map(item -> new ImpactedPackage(item.findElement(By.className("impacted-package-id")).getText(),
                getVersions(item.findElement(By.className("impacted-package-affected"))),
                getVersions(item.findElement(By.className("impacted-package-patched")))))
            .toList();
    }

    /**
     * @param rowNumber the number of the row of the advisory, starting at 1
     * @return the patched versions of all the packages impacted by the advisory, as displayed in the patched versions
     *     column: each version once, in the order of the impacted packages
     * @since 2.3.1
     */
    public List<String> getPatchedVersions(int rowNumber)
    {
        return getVersions(getAdvisories().getTableLayout().getCell(PATCHED_VERSIONS_COLUMN, rowNumber));
    }

    private List<String> getVersions(WebElement container)
    {
        return container.findElements(VERSION_BADGES).stream().map(WebElement::getText).toList();
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
