/**
 * Unit tests for parsing utilities - date parsing, duration parsing, and natural language processing
 */
import { describe, it, expect, beforeEach, jest, afterEach } from '@jest/globals';
import {
  isLeaveRequest,
  parseDateRange,
  parseDuration,
  parseDate,
  parseTimeEntry,
  LEAVE_PATTERNS,
} from '../parsers.js';
import { McpError } from '@modelcontextprotocol/sdk/types.js';

describe('Parser Utilities', () => {
  const TIMEZONE = 'Australia/Perth';
  const STANDARD_WORK_DAY_HOURS = 7.5;

  describe('isLeaveRequest', () => {
    it('should detect sick leave', () => {
      expect(isLeaveRequest('sick leave today')).toEqual({
        isLeave: true,
        type: 'sick',
      });
    });

    it('should detect sick leave with "ill" keyword', () => {
      expect(isLeaveRequest('I was ill today')).toEqual({
        isLeave: true,
        type: 'sick',
      });
    });

    it('should detect sick leave with "unwell" keyword', () => {
      expect(isLeaveRequest('feeling unwell')).toEqual({
        isLeave: true,
        type: 'sick',
      });
    });

    it('should detect annual leave', () => {
      expect(isLeaveRequest('annual leave today')).toEqual({
        isLeave: true,
        type: 'annual',
      });
    });

    it('should detect vacation', () => {
      expect(isLeaveRequest('on vacation today')).toEqual({
        isLeave: true,
        type: 'annual',
      });
    });

    it('should detect holiday', () => {
      expect(isLeaveRequest('taking a holiday')).toEqual({
        isLeave: true,
        type: 'annual',
      });
    });

    it('should detect time off', () => {
      expect(isLeaveRequest('time off today')).toEqual({
        isLeave: true,
        type: 'annual',
      });
    });

    it('should not detect leave in regular time entry', () => {
      expect(isLeaveRequest('2 hours on Project X')).toEqual({
        isLeave: false,
      });
    });

    it('should be case insensitive', () => {
      expect(isLeaveRequest('SICK LEAVE')).toEqual({
        isLeave: true,
        type: 'sick',
      });
    });
  });

  describe('parseDuration', () => {
    it('should parse integer hours', () => {
      expect(parseDuration('2 hours')).toBe(2);
    });

    it('should parse decimal hours', () => {
      expect(parseDuration('1.5 hours')).toBe(1.5);
      expect(parseDuration('2.25 hours')).toBe(2.25);
    });

    it('should parse "hour" singular', () => {
      expect(parseDuration('1 hour')).toBe(1);
    });

    it('should parse "hr" abbreviation', () => {
      expect(parseDuration('3 hr')).toBe(3);
      expect(parseDuration('2.5 hr')).toBe(2.5);
    });

    it('should parse "h" abbreviation', () => {
      expect(parseDuration('4h')).toBe(4);
      expect(parseDuration('1.75h')).toBe(1.75);
    });

    it('should parse minutes and convert to hours', () => {
      expect(parseDuration('30 minutes')).toBe(0.5);
      expect(parseDuration('60 minutes')).toBe(1);
      expect(parseDuration('90 minutes')).toBe(1.5);
      expect(parseDuration('15 minutes')).toBe(0.25);
    });

    it('should parse "min" abbreviation', () => {
      expect(parseDuration('45 min')).toBe(0.75);
    });

    it('should parse "m" abbreviation', () => {
      expect(parseDuration('20m')).toBe(20 / 60);
    });

    it('should handle variations in spacing', () => {
      expect(parseDuration('2hours')).toBe(2);
      expect(parseDuration('3 hrs')).toBe(3);
    });

    it('should be case insensitive', () => {
      expect(parseDuration('2 HOURS')).toBe(2);
      expect(parseDuration('30 MINUTES')).toBe(0.5);
    });

    it('should throw error when duration cannot be parsed', () => {
      expect(() => parseDuration('some time')).toThrow(McpError);
      expect(() => parseDuration('some time')).toThrow('Could not parse duration from input');
    });

    it('should throw error for invalid format', () => {
      expect(() => parseDuration('no numbers here')).toThrow(McpError);
    });
  });

  describe('parseDate', () => {
    it('should parse "today" to current date', () => {
      const result = parseDate('today', TIMEZONE);
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('should parse "yesterday"', () => {
      const result = parseDate('yesterday', TIMEZONE);
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/);

      // Verify it's a valid date (chrono handles the parsing)
      const today = new Date(new Date().toLocaleString('en-US', { timeZone: TIMEZONE }));
      const todayStr = today.toISOString().split('T')[0];
      // Result should be a date (not today)
      expect(result).not.toBe(todayStr);
    });

    it('should parse specific dates', () => {
      const result = parseDate('November 10th 2025', TIMEZONE);
      expect(result).toBe('2025-11-10');
    });

    it('should parse relative dates', () => {
      const result = parseDate('last Friday', TIMEZONE);
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('should parse dates with context', () => {
      const result = parseDate('2 hours on Project X yesterday', TIMEZONE);
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('should return YYYY-MM-DD format', () => {
      const result = parseDate('today', TIMEZONE);
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/);

      const parts = result.split('-');
      expect(parts).toHaveLength(3);
      expect(parts[0]).toHaveLength(4); // year
      expect(parts[1]).toHaveLength(2); // month
      expect(parts[2]).toHaveLength(2); // day
    });

    it('should throw error when date cannot be parsed', () => {
      expect(() => parseDate('asdfghjkl', TIMEZONE)).toThrow(McpError);
      expect(() => parseDate('asdfghjkl', TIMEZONE)).toThrow('Could not parse date from input');
    });
  });

  describe('parseDateRange', () => {
    it('should parse "last month"', () => {
      const result = parseDateRange('last month', TIMEZONE);

      expect(result.from).toMatch(/^\d{4}-\d{2}-01$/);
      expect(result.to).toMatch(/^\d{4}-\d{2}-\d{2}$/);

      // Verify it's actually last month
      const now = new Date(new Date().toLocaleString('en-US', { timeZone: TIMEZONE }));
      const expectedFrom = new Date(now.getFullYear(), now.getMonth() - 1, 1);
      expect(result.from).toBe(expectedFrom.toISOString().split('T')[0]);
    });

    it('should parse "this month"', () => {
      const result = parseDateRange('this month', TIMEZONE);

      expect(result.from).toMatch(/^\d{4}-\d{2}-01$/);
      expect(result.to).toMatch(/^\d{4}-\d{2}-\d{2}$/);

      // Verify it's actually this month
      const now = new Date(new Date().toLocaleString('en-US', { timeZone: TIMEZONE }));
      const expectedFrom = new Date(now.getFullYear(), now.getMonth(), 1);
      expect(result.from).toBe(expectedFrom.toISOString().split('T')[0]);
    });

    it('should parse "this week"', () => {
      const result = parseDateRange('this week', TIMEZONE);

      expect(result.from).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(result.to).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('should parse "last week"', () => {
      const result = parseDateRange('last week', TIMEZONE);

      expect(result.from).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(result.to).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });

    it('should parse custom date ranges with chrono', () => {
      const result = parseDateRange('from November 1 to November 7 2025', TIMEZONE);

      expect(result.from).toBe('2025-11-01');
      expect(result.to).toBe('2025-11-07');
    });

    it('should use start date as end date if no end specified', () => {
      const result = parseDateRange('on November 15 2025', TIMEZONE);

      expect(result.from).toBe('2025-11-15');
      expect(result.to).toBe('2025-11-15');
    });

    it('should throw error when date range cannot be parsed', () => {
      expect(() => parseDateRange('asdfghjkl', TIMEZONE)).toThrow(McpError);
      expect(() => parseDateRange('asdfghjkl', TIMEZONE)).toThrow('Could not parse date range from input');
    });

    it('should return dates in YYYY-MM-DD format', () => {
      const result = parseDateRange('this month', TIMEZONE);

      expect(result.from).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(result.to).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });
  });

  describe('parseTimeEntry', () => {
    describe('Regular Time Entries', () => {
      it('should parse complete time entry with all details', () => {
        const result = parseTimeEntry('2 hours on Project X today', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(2);
        expect(result.spent_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(result.isLeave).toBe(false);
        expect(result.leaveType).toBeUndefined();
      });

      it('should parse entry with yesterday', () => {
        const result = parseTimeEntry('3 hours on Project X yesterday', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(3);
        expect(result.isLeave).toBe(false);
      });

      it('should parse entry with specific date', () => {
        const result = parseTimeEntry('4 hours on Project X on November 10 2025', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(4);
        expect(result.spent_date).toBe('2025-11-10');
        expect(result.isLeave).toBe(false);
      });

      it('should parse entry with decimal hours', () => {
        const result = parseTimeEntry('1.5 hours on Project X today', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(1.5);
        expect(result.isLeave).toBe(false);
      });

      it('should parse entry with minutes', () => {
        const result = parseTimeEntry('30 minutes on Project X today', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(0.5);
        expect(result.isLeave).toBe(false);
      });

      it('should parse entry with abbreviated units', () => {
        const result = parseTimeEntry('2.5h on Project X today', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(2.5);
        expect(result.isLeave).toBe(false);
      });
    });

    describe('Leave Requests', () => {
      it('should parse sick leave request', () => {
        const result = parseTimeEntry('sick leave today', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(STANDARD_WORK_DAY_HOURS);
        expect(result.spent_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(result.isLeave).toBe(true);
        expect(result.leaveType).toBe('sick');
      });

      it('should parse sick leave with "ill"', () => {
        const result = parseTimeEntry('I was ill', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(STANDARD_WORK_DAY_HOURS);
        expect(result.isLeave).toBe(true);
        expect(result.leaveType).toBe('sick');
      });

      it('should parse annual leave request', () => {
        const result = parseTimeEntry('annual leave today', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(STANDARD_WORK_DAY_HOURS);
        expect(result.isLeave).toBe(true);
        expect(result.leaveType).toBe('annual');
      });

      it('should parse vacation request', () => {
        const result = parseTimeEntry('on vacation', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        expect(result.hours).toBe(STANDARD_WORK_DAY_HOURS);
        expect(result.isLeave).toBe(true);
        expect(result.leaveType).toBe('annual');
      });

      it('should use custom standard work day hours', () => {
        const result = parseTimeEntry('sick leave today', 8, TIMEZONE);

        expect(result.hours).toBe(8);
        expect(result.isLeave).toBe(true);
      });

      it('should always use today for leave requests', () => {
        const result = parseTimeEntry('sick leave', STANDARD_WORK_DAY_HOURS, TIMEZONE);

        const today = new Date(new Date().toLocaleString('en-US', { timeZone: TIMEZONE }));
        expect(result.spent_date).toBe(today.toISOString().split('T')[0]);
      });
    });

    describe('Error Handling', () => {
      it('should throw error when duration missing', () => {
        expect(() => parseTimeEntry('on Project X today', STANDARD_WORK_DAY_HOURS, TIMEZONE)).toThrow(McpError);
        expect(() => parseTimeEntry('on Project X today', STANDARD_WORK_DAY_HOURS, TIMEZONE)).toThrow('Could not parse duration from input');
      });

      it('should throw error when date invalid', () => {
        expect(() => parseTimeEntry('2 hours on asdfghjkl', STANDARD_WORK_DAY_HOURS, TIMEZONE)).toThrow(McpError);
        expect(() => parseTimeEntry('2 hours on asdfghjkl', STANDARD_WORK_DAY_HOURS, TIMEZONE)).toThrow('Could not parse date from input');
      });
    });
  });

  describe('LEAVE_PATTERNS constant', () => {
    it('should export sick leave patterns', () => {
      expect(LEAVE_PATTERNS.sick).toBeDefined();
      expect(LEAVE_PATTERNS.sick.triggers).toContain('sick');
      expect(LEAVE_PATTERNS.sick.project).toBe('[LV] Leave');
      expect(LEAVE_PATTERNS.sick.task).toBe("Person (Sick/Carer's) Leave");
    });

    it('should export annual leave patterns', () => {
      expect(LEAVE_PATTERNS.annual).toBeDefined();
      expect(LEAVE_PATTERNS.annual.triggers).toContain('annual leave');
      expect(LEAVE_PATTERNS.annual.triggers).toContain('vacation');
      expect(LEAVE_PATTERNS.annual.project).toBe('[LV] Leave');
      expect(LEAVE_PATTERNS.annual.task).toBe('Annual Leave');
    });
  });

  describe('Integration Tests', () => {
    it('should handle complex time entry text', () => {
      const result = parseTimeEntry(
        '2.5 hours on Project Alpha doing development work yesterday',
        STANDARD_WORK_DAY_HOURS,
        TIMEZONE
      );

      expect(result.hours).toBe(2.5);
      expect(result.spent_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(result.isLeave).toBe(false);
    });

    it('should prioritize leave detection over duration parsing', () => {
      const result = parseTimeEntry('sick leave', STANDARD_WORK_DAY_HOURS, TIMEZONE);

      // Should be leave request, not try to parse "sick" as duration
      expect(result.isLeave).toBe(true);
      expect(result.hours).toBe(STANDARD_WORK_DAY_HOURS);
    });

    it('should handle different timezones', () => {
      const resultPerth = parseTimeEntry('2 hours today', STANDARD_WORK_DAY_HOURS, 'Australia/Perth');
      const resultNY = parseTimeEntry('2 hours today', STANDARD_WORK_DAY_HOURS, 'America/New_York');

      // Both should be valid dates, might be different days due to timezone
      expect(resultPerth.spent_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(resultNY.spent_date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(resultPerth.hours).toBe(2);
      expect(resultNY.hours).toBe(2);
    });
  });
});
