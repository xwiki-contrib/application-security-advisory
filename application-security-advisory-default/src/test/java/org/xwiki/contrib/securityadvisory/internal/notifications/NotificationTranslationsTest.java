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
package org.xwiki.contrib.securityadvisory.internal.notifications;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.xwiki.eventstream.RecordableEventDescriptor;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Checks that the notification events of the application provide all the translations used by the notification
 * templates to display them.
 *
 * @version $Id$
 */
class NotificationTranslationsTest
{
    private static final Properties TRANSLATIONS = new Properties();

    @BeforeAll
    static void loadTranslations() throws IOException
    {
        try (InputStream inputStream =
            NotificationTranslationsTest.class.getResourceAsStream("/ApplicationResources.properties"))
        {
            TRANSLATIONS.load(inputStream);
        }
    }

    static Stream<RecordableEventDescriptor> eventDescriptors()
    {
        return Stream.of(new AnnouncedAdvisoryEventDescriptor(), new SecurityAdvisoryDisclosableEventDescriptor(),
            new SecurityAdvisoryEmbargoDateEventDescriptor());
    }

    /**
     * The notification templates display grouped events with the {@code description.by.1user} key when they were
     * triggered by a single user, and with the {@code description.by.users} key otherwise.
     */
    @ParameterizedTest
    @MethodSource("eventDescriptors")
    void notificationDescriptionTranslations(RecordableEventDescriptor descriptor)
    {
        String prefix = "notifications.events." + descriptor.getEventType() + ".description";
        for (String key : new String[] { prefix, prefix + ".by.1user", prefix + ".by.users" }) {
            assertTrue(TRANSLATIONS.containsKey(key), String.format("Missing translation key [%s]", key));
        }
        assertTrue(TRANSLATIONS.containsKey(descriptor.getDescription()),
            String.format("Missing translation key [%s]", descriptor.getDescription()));
    }
}
