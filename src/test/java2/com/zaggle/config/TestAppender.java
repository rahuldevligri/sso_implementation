package com.zaggle.config;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import lombok.Getter;

import java.util.ArrayList;
import java.util.List;

@Getter
public class TestAppender extends AppenderBase<ILoggingEvent> {
    private final List<ILoggingEvent> events = new ArrayList<>();

    /**
     * append method for appending error logs.
     * @param eventObject
     */
    @Override
    protected void append(final ILoggingEvent eventObject) {
        events.add(eventObject);
    }

    /**
     * getEvents method for getting the events.
     * @return List<ILoggingEvent>
     */
    public List<ILoggingEvent> getEvents() {
        return events;
    }
}

