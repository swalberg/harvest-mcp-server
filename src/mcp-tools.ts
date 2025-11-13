/**
 * MCP tool handlers for Harvest operations
 */
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import * as chrono from 'chrono-node';
import axios from 'axios';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { HarvestClient } from './harvest-client.js';
import { Config } from './config.js';
import { Logger } from './logger.js';

// Special patterns for leave requests
const LEAVE_PATTERNS = {
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
};

export class McpToolHandlers {
  private config: Config;
  private logger: Logger;

  constructor(config: Config, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }

  private isLeaveRequest(text: string): { isLeave: boolean; type?: keyof typeof LEAVE_PATTERNS } {
    const lowercaseText = text.toLowerCase();
    for (const [type, pattern] of Object.entries(LEAVE_PATTERNS)) {
      if (pattern.triggers.some(trigger => lowercaseText.includes(trigger))) {
        return { isLeave: true, type: type as keyof typeof LEAVE_PATTERNS };
      }
    }
    return { isLeave: false };
  }

  private parseDateRange(text: string): { from: string; to: string } {
    const lowercaseText = text.toLowerCase();
    const now = new Date(new Date().toLocaleString('en-US', { timeZone: this.config.timezone }));

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

  private async parseTimeEntry(text: string) {
    const lowercaseText = text.toLowerCase();
    const now = new Date(new Date().toLocaleString('en-US', { timeZone: this.config.timezone }));

    // Check if this is a leave request
    const leaveCheck = this.isLeaveRequest(text);
    if (leaveCheck.isLeave && leaveCheck.type) {
      // For leave requests, use the full work day
      return {
        spent_date: now.toISOString().split('T')[0],
        hours: this.config.standardWorkDayHours,
        isLeave: true,
        leaveType: leaveCheck.type
      };
    }

    // For regular time entries
    let date: Date;
    if (lowercaseText.includes('today')) {
      date = now;
    } else {
      const parsed = chrono.parseDate(text);
      if (!parsed) {
        throw new McpError(ErrorCode.InvalidParams, 'Could not parse date from input');
      }
      date = parsed;
    }

    // Extract hours/minutes
    const durationMatch = text.match(/(\d+(?:\.\d+)?)\s*(hour|hr|h|minute|min|m)s?/i);
    if (!durationMatch) {
      throw new McpError(ErrorCode.InvalidParams, 'Could not parse duration from input');
    }

    const amount = parseFloat(durationMatch[1]);
    const unit = durationMatch[2].toLowerCase();
    const hours = unit.startsWith('h') ? amount : amount / 60;

    return {
      spent_date: date.toISOString().split('T')[0],
      hours,
      isLeave: false
    };
  }

  private async findProjectAndTasks(
    client: HarvestClient,
    text: string,
    isLeave: boolean = false,
    leaveType?: keyof typeof LEAVE_PATTERNS
  ): Promise<{ projectId: number; taskAssignments: any[] }> {
    const projectAssignments = await client.getProjectAssignments();

    if (isLeave && leaveType) {
      // For leave requests, look for the specific leave project
      const leaveProjectAssignment = projectAssignments.find((pa: { project: { name: string; id: number }; task_assignments: any[] }) =>
        pa.project.name === LEAVE_PATTERNS[leaveType].project
      );
      if (leaveProjectAssignment) {
        return {
          projectId: leaveProjectAssignment.project.id,
          taskAssignments: leaveProjectAssignment.task_assignments
        };
      }
    }

    // For regular entries or if leave project not found
    const projectMatch = projectAssignments.find((pa: { project: { name: string; code: string; id: number }; task_assignments: any[] }) => {
      const lowerText = text.toLowerCase();
      return lowerText.includes(pa.project.name.toLowerCase()) ||
             (pa.project.code && lowerText.includes(pa.project.code.toLowerCase()));
    });

    if (!projectMatch) {
      throw new McpError(ErrorCode.InvalidParams, 'Could not find matching project');
    }

    return {
      projectId: projectMatch.project.id,
      taskAssignments: projectMatch.task_assignments
    };
  }

  private findTask(
    taskAssignments: any[],
    text: string,
    isLeave: boolean = false,
    leaveType?: keyof typeof LEAVE_PATTERNS
  ): number {
    if (isLeave && leaveType) {
      // For leave requests, look for the specific leave task
      const leaveTask = taskAssignments.find((t: { task: { name: string; id: number } }) =>
        t.task.name === LEAVE_PATTERNS[leaveType].task
      );
      if (leaveTask) {
        return leaveTask.task.id;
      }
    }

    // For regular entries or if leave task not found
    const taskMatch = taskAssignments.find((t: { task: { name: string; id: number } }) =>
      text.toLowerCase().includes(t.task.name.toLowerCase())
    );

    if (!taskMatch) {
      // Default to first task if no match found
      return taskAssignments[0].task.id;
    }

    return taskMatch.task.id;
  }

  setupHandlers(server: Server, getClient: () => HarvestClient | null) {
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'log_time',
          description: 'Log time entry using natural language',
          inputSchema: {
            type: 'object',
            properties: {
              text: {
                type: 'string',
                description: 'Natural language time entry (e.g. "2 hours on Project X doing development work yesterday")',
              },
            },
            required: ['text'],
          },
        },
        {
          name: 'list_projects',
          description: 'List available Harvest projects',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'list_tasks',
          description: 'List available tasks for a project',
          inputSchema: {
            type: 'object',
            properties: {
              project_id: {
                type: 'number',
                description: 'Project ID',
              },
            },
            required: ['project_id'],
          },
        },
        {
          name: 'list_entries',
          description: 'List recent time entries',
          inputSchema: {
            type: 'object',
            properties: {
              from: {
                type: 'string',
                description: 'Start date (YYYY-MM-DD)',
              },
              to: {
                type: 'string',
                description: 'End date (YYYY-MM-DD)',
              },
            },
          },
        },
        {
          name: 'get_time_report',
          description: 'Get time reports using natural language',
          inputSchema: {
            type: 'object',
            properties: {
              text: {
                type: 'string',
                description: 'Natural language query (e.g., "Show time report for last month", "Get time summary for Project X")',
              },
            },
            required: ['text'],
          },
        },
      ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const client = getClient();
      if (!client) {
        throw new McpError(ErrorCode.InvalidRequest, 'Not authenticated');
      }

      switch (request.params.name) {
        case 'log_time': {
          const { text } = request.params.arguments as { text: string };

          try {
            this.logger.info({ tool: 'log_time', text }, 'Processing log_time request');

            // Parse time entry details
            const { spent_date, hours, isLeave, leaveType } = await this.parseTimeEntry(text);

            // Find matching project and get task assignments
            const { projectId: project_id, taskAssignments } = await this.findProjectAndTasks(client, text, isLeave, leaveType);

            // Find matching task
            const task_id = this.findTask(taskAssignments, text, isLeave, leaveType);

            // Create time entry
            const entry = await client.createTimeEntry({
              project_id,
              task_id,
              spent_date,
              hours,
              notes: text,
            });

            this.logger.info({ entryId: entry.id, hours, project_id, task_id }, 'Time entry created successfully');

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(entry, null, 2),
                },
              ],
            };
          } catch (error) {
            this.logger.error({ error, tool: 'log_time' }, 'Error processing log_time request');
            if (error instanceof McpError) {
              throw error;
            }
            if (axios.isAxiosError(error)) {
              throw new McpError(
                ErrorCode.InternalError,
                `Harvest API error: ${error.response?.data?.message ?? error.message}`
              );
            }
            throw error;
          }
        }

        case 'list_projects': {
          this.logger.info({ tool: 'list_projects' }, 'Processing list_projects request');
          const projectAssignments = await client.getProjectAssignments();
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(projectAssignments.map((p: {project: { id: number; name: string; code: string; }, is_active: boolean}) => ({
                  id: p.project.id,
                  name: p.project.name,
                  code: p.project.code,
                  is_active: p.is_active,
                })), null, 2),
              },
            ],
          };
        }

        case 'list_tasks': {
          const { project_id } = request.params.arguments as { project_id: number };
          this.logger.info({ tool: 'list_tasks', project_id }, 'Processing list_tasks request');
          const taskAssignments = await client.getTaskAssignments(project_id);
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(taskAssignments.map((t: { task: { id: number; name: string } }) => ({
                  id: t.task.id,
                  name: t.task.name,
                })), null, 2),
              },
            ],
          };
        }

        case 'list_entries': {
          const { from, to } = request.params.arguments as { from?: string; to?: string };
          this.logger.info({ tool: 'list_entries', from, to }, 'Processing list_entries request');

          const params: { from?: string; to?: string } = {};
          if (from) params.from = from;
          if (to) params.to = to;

          const entries = await client.listTimeEntries(params);
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(entries.map((e: { id: number; spent_date: string; hours: number; notes: string; project: { name: string }; task: { name: string } }) => ({
                  id: e.id,
                  spent_date: e.spent_date,
                  hours: e.hours,
                  notes: e.notes,
                  project: e.project.name,
                  task: e.task.name,
                })), null, 2),
              },
            ],
          };
        }

        case 'get_time_report': {
          const { text } = request.params.arguments as { text: string };

          try {
            this.logger.info({ tool: 'get_time_report', text }, 'Processing get_time_report request');

            const { from, to } = this.parseDateRange(text);
            const lowercaseText = text.toLowerCase();

            let endpoint = '/reports/time/projects'; // default to project report

            if (lowercaseText.includes('by client') || lowercaseText.includes('for client')) {
              endpoint = '/reports/time/clients';
            } else if (lowercaseText.includes('by task') || lowercaseText.includes('tasks')) {
              endpoint = '/reports/time/tasks';
            } else if (lowercaseText.includes('by team') || lowercaseText.includes('by user')) {
              endpoint = '/reports/time/team';
            }

            const report = await client.getTimeReport(endpoint, { from, to });

            this.logger.info({ endpoint, from, to }, 'Time report generated successfully');

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(report, null, 2),
                },
              ],
            };
          } catch (error) {
            this.logger.error({ error, tool: 'get_time_report' }, 'Error processing get_time_report request');
            if (error instanceof McpError) {
              throw error;
            }
            if (axios.isAxiosError(error)) {
              throw new McpError(
                ErrorCode.InternalError,
                `Harvest API error: ${error.response?.data?.message ?? error.message}`
              );
            }
            throw error;
          }
        }

        default:
          throw new McpError(
            ErrorCode.MethodNotFound,
            `Unknown tool: ${request.params.name}`
          );
      }
    });
  }
}
