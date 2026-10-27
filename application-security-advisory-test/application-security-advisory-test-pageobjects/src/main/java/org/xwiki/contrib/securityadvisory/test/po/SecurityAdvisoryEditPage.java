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
import org.openqa.selenium.WebElement;
import org.xwiki.test.ui.po.FormContainerElement;
import org.xwiki.test.ui.po.InlinePage;

/**
 * Represents the edit form of an advisory.
 *
 * @version $Id$
 * @since 2.2.2
 */
public class SecurityAdvisoryEditPage extends InlinePage
{
    private static final String FIELD_PREFIX = SecurityAdvisoryViewPage.ADVISORY_CLASS + "_0_";

    /**
     * @param title the title of the advisory
     */
    public void setTitle(String title)
    {
        WebElement titleInput = getForm().findElement(By.id(FIELD_PREFIX + "title1"));
        titleInput.clear();
        titleInput.sendKeys(title);
    }

    /**
     * @param computeEmbargoDate {@code true} to have the embargo date computed from the release dates of the patched
     *     versions, {@code false} otherwise
     */
    public void setComputeEmbargoDate(boolean computeEmbargoDate)
    {
        new FormContainerElement(getFormLocator()).setCheckBox(
            By.cssSelector(String.format("input[type='checkbox'][name='%scomputeEmbargo']", FIELD_PREFIX)),
            computeEmbargoDate);
    }

    /**
     * Save the advisory and view it.
     *
     * @return the view of the saved advisory
     */
    public SecurityAdvisoryViewPage save()
    {
        clickSaveAndView(true);
        return new SecurityAdvisoryViewPage();
    }
}
