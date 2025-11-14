/**
 * Parsing utilities for natural language time entries and date ranges
 */
import * as chrono from 'chrono-node';
import { ErrorCode, McpError } from '@modelcontextprotocol/sdk/types.js';

// Special patterns for leave requests
export const LEAVE_PATTERNS = {
  sick: {
    triggers: ['sick', 'ill', 'unwell'],
    project: '[LV] Leave',
    task: "Person (Sick/Carer's) Leave",
  },
  annual: {
    triggers: ['annual leave', 'vacation', 'holiday', 'time off'],
    project: '[LV] Leave',
    task: 'Annual Leave',
  }
} as const;

export type LeaveType = keyof typeof LEAVE_PATTERNS;

export interface ParsedTimeEntry {
  spent_date: string;
  hours: number;
  isLeave: boolean;
  leaveType?: LeaveType;
}

export interface DateRange {
  from: string;
  to: string;
}

export interface LeaveCheckResult {
  isLeave: boolean;
  type?: LeaveType;
}

/**
 * Check if text contains leave request keywords
 */
export function isLeaveRequest(text: string): LeaveCheckResult {
  const lowercaseText = text.toLowerCase();
  for (const [type, pattern] of Object.entries(LEAVE_PATTERNS)) {
    if (pattern.triggers.some(trigger => lowercaseText.includes(trigger))) {
      return { isLeave: true, type: type as LeaveType };
    }
  }
  return { isLeave: false };
}

/**
 * Parse date range from natural language text
 */
export function parseDateRange(text: string, timezone: string): DateRange {
  const lowercaseText = text.toLowerCase();
  const now = new Date(new Date().toLocaleString('en-US', { timeZone: timezone }));

  // Handle common time ranges
  if (lowercaseText.includes('last month')) {
    const from = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const to = new Date(now.getFullYear(), now.getMonth(), 0);
    return {
      from: from.toISOString().split('T')[0],
      to: to.toISOString().split('T')[0]
    };
  }

  if (lowercaseText.includes('this month')) {
    const from = new Date(now.getFullYear(), now.getMonth(), 1);
    const to = now;
    return {
      from: from.toISOString().split('T')[0],
      to: to.toISOString().split('T')[0]
    };
  }

  if (lowercaseText.includes('this week')) {
    const from = new Date(now);
    from.setDate(now.getDate() - now.getDay());
    return {
      from: from.toISOString().split('T')[0],
      to: now.toISOString().split('T')[0]
    };
  }

  if (lowercaseText.includes('last week')) {
    const from = new Date(now);
    from.setDate(now.getDate() - now.getDay() - 7);
    const to = new Date(from);
    to.setDate(from.getDate() + 6);
    return {
      from: from.toISOString().split('T')[0],
      to: to.toISOString().split('T')[0]
    };
  }

  // Default to parsing with chrono
  const dates = chrono.parse(text);
  if (dates.length === 0) {
    throw new McpError(ErrorCode.InvalidParams, 'Could not parse date range from input');
  }

  return {
    from: dates[0].start.date().toISOString().split('T')[0],
    to: (dates[0].end?.date() || dates[0].start.date()).toISOString().split('T')[0]
  };
}

/**
 * Parse duration from text (e.g., "2 hours", "30 minutes", "1.5h")
 * Returns hours as a decimal number
 */
export function parseDuration(text: string): number {
  const durationMatch = text.match(/(\d+(?:\.\d+)?)\s*(hour|hr|h|minute|min|m)s?/i);
  if (!durationMatch) {
    throw new McpError(ErrorCode.InvalidParams, 'Could not parse duration from input');
  }

  const amount = parseFloat(durationMatch[1]);
  const unit = durationMatch[2].toLowerCase();
  const hours = unit.startsWith('h') ? amount : amount / 60;

  return hours;
}

/**
 * Parse date from text, returns ISO date string (YYYY-MM-DD)
 */
export function parseDate(text: string, timezone: string): string {
  const lowercaseText = text.toLowerCase();
  const now = new Date(new Date().toLocaleString('en-US', { timeZone: timezone }));

  // Handle "today" explicitly
  if (lowercaseText.includes('today')) {
    return now.toISOString().split('T')[0];
  }

  // Use chrono for other date formats
  const parsed = chrono.parseDate(text);
  if (!parsed) {
    throw new McpError(ErrorCode.InvalidParams, 'Could not parse date from input');
  }

  return parsed.toISOString().split('T')[0];
}

/**
 * Parse time entry from natural language text
 */
export function parseTimeEntry(text: string, standardWorkDayHours: number, timezone: string): ParsedTimeEntry {
  // Check if this is a leave request
  const leaveCheck = isLeaveRequest(text);
  if (leaveCheck.isLeave && leaveCheck.type) {
    // For leave requests, use the full work day and today's date
    const now = new Date(new Date().toLocaleString('en-US', { timeZone: timezone }));
    return {
      spent_date: now.toISOString().split('T')[0],
      hours: standardWorkDayHours,
      isLeave: true,
      leaveType: leaveCheck.type
    };
  }

  // For regular time entries, parse date and duration
  const spent_date = parseDate(text, timezone);
  const hours = parseDuration(text);

  return {
    spent_date,
    hours,
    isLeave: false
  };
}
