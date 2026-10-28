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

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.ui.po.ViewPage;

/**
 * Represents the view of an advisory.
 *
 * @version $Id$
 * @since 2.3
 */
public class SecurityAdvisoryViewPage extends ViewPage
{
    /**
     * The class holding the advisory data.
     */
    public static final String ADVISORY_CLASS = "SecurityAdvisoryApplication.Code.SecurityAdvisoryApplicationClass";

    /**
     * The class holding the data of each package impacted by an advisory.
     */
    public static final String IMPACTED_PACKAGE_CLASS =
        "SecurityAdvisoryApplication.Code.SecurityAdvisoryImpactedPackageClass";

    // The format of the date properties of the advisory class.
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("dd/MM/yyyy");

    // The value of an editable property is displayed right after its label, which names the property it displays.
    private static final String PROPERTY_VALUE_SELECTOR = "dt[data-property$='.%s'] + dd";

    /**
     * Go to the view of the given advisory.
     *
     * @param advisoryReference the page holding the advisory
     * @return the view of the advisory
     */
    public static SecurityAdvisoryViewPage gotoPage(DocumentReference advisoryReference)
    {
        getUtil().gotoPage(advisoryReference);
        return new SecurityAdvisoryViewPage();
    }

    /**
     * @return the page holding the advisory
     */
    public DocumentReference getAdvisoryReference()
    {
        return new DocumentReference(getUtil().resolveDocumentReference(getMetaDataValue("reference")));
    }

    /**
     * @return the status of the advisory, displayed next to its title
     */
    public SecurityAdvisory.State getStatus()
    {
        String status = getDriver().findElement(By.cssSelector("span.advisory-status")).getText();
        return SecurityAdvisory.State.valueOf(status.trim().toUpperCase(Locale.ROOT));
    }

    /**
     * @return the embargo date of the advisory, or {@link Optional#empty()} if it's not set
     */
    public Optional<LocalDate> getEmbargoDate()
    {
        String embargoDate = getPropertyValue("embargoDate").getText().trim();
        return StringUtils.isEmpty(embargoDate) ? Optional.empty()
            : Optional.of(LocalDate.parse(embargoDate, DATE_FORMAT));
    }

    /**
     * @param packageId the identifier of an impacted package of the advisory
     * @return the patched versions of the given package, in the displayed order, mapped to {@code true} when they are
     *     marked as released and {@code false} otherwise
     */
    public Map<String, Boolean> getPatchedVersions(String packageId)
    {
        // Each impacted package displays its identifier and then its patched versions, in the same order.
        List<WebElement> packageIds = findPropertyValues("packageId");
        List<WebElement> patchedVersions = findPropertyValues("patchedVersions");
        for (int i = 0; i < packageIds.size(); i++) {
            if (packageId.equals(packageIds.get(i).getText().trim())) {
                return getVersionsReleaseStatus(patchedVersions.get(i));
            }
        }
        throw new IllegalArgumentException(String.format("No impacted package [%s] is displayed.", packageId));
    }

    private Map<String, Boolean> getVersionsReleaseStatus(WebElement versionList)
    {
        Map<String, Boolean> result = new LinkedHashMap<>();
        for (WebElement versionItem : versionList.findElements(By.cssSelector("ul.version-list > li"))) {
            WebElement releaseLabel = versionItem.findElement(By.className("label"));
            String version = Strings.CS.removeEnd(versionItem.getText().trim(), releaseLabel.getText()).trim();
            result.put(version, releaseLabel.getAttribute("class").contains("label-success"));
        }
        return result;
    }

    /**
     * Mark the draft advisory as completed.
     *
     * @return the view of the advisory, reloaded with its new status
     */
    public SecurityAdvisoryViewPage markCompleted()
    {
        return clickStatusButton("btn-complete");
    }

    /**
     * Mark the completed advisory as announced.
     *
     * @return the view of the advisory, reloaded with its new status
     */
    public SecurityAdvisoryViewPage markAnnounced()
    {
        return clickStatusButton("btn-announce");
    }

    /**
     * @return {@code true} if the action to mark the advisory as disclosed is available, {@code false} otherwise
     */
    public boolean canMarkDisclosed()
    {
        return getDriver().hasElementWithoutWaiting(By.cssSelector("button.btn-disclose"));
    }

    /**
     * Reload the advisory until it gets the given status, for status changed by a background computation, such as
     * the one marking the advisories disclosable.
     *
     * @param status the expected status
     * @return the view of the advisory with the expected status
     */
    public SecurityAdvisoryViewPage reloadUntilStatus(SecurityAdvisory.State status)
    {
        DocumentReference advisoryReference = getAdvisoryReference();
        getDriver().waitUntilCondition(driver -> gotoPage(advisoryReference).getStatus() == status);
        return new SecurityAdvisoryViewPage();
    }

    private SecurityAdvisoryViewPage clickStatusButton(String buttonClass)
    {
        getDriver().addPageNotYetReloadedMarker();
        getDriver().findElement(By.cssSelector("button." + buttonClass)).click();
        // The status is changed with an asynchronous request, and the page is reloaded once it is done.
        getDriver().waitUntilPageIsReloaded();
        return new SecurityAdvisoryViewPage();
    }

    private WebElement getPropertyValue(String propertyName)
    {
        return getDriver().findElement(By.cssSelector(String.format(PROPERTY_VALUE_SELECTOR, propertyName)));
    }

    private List<WebElement> findPropertyValues(String propertyName)
    {
        return getDriver().findElementsWithoutWaiting(
            By.cssSelector(String.format(PROPERTY_VALUE_SELECTOR, propertyName)));
    }
}
