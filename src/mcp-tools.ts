/**
 * MCP tool handlers for Harvest operations
 */
import {
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { HarvestClient } from './harvest-client.js';
import { Config } from './config.js';
import { Logger } from './logger.js';
import { parseTimeEntry, parseDateRange, LEAVE_PATTERNS, LeaveType } from './parsers.js';

export class McpToolHandlers {
  private config: Config;
  private logger: Logger;

  constructor(config: Config, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }


  private async findProjectAndTasks(
    client: HarvestClient,
    text: string,
    isLeave: boolean = false,
    leaveType?: LeaveType
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
    leaveType?: LeaveType
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

  setupHandlers(server: McpServer, getClient: () => HarvestClient | null) {
    // Register log_time tool
    server.registerTool(
      'log_time',
      {
        description: 'Log time entry using natural language',
        inputSchema: {
          text: z.string().describe('Natural language time entry (e.g. "2 hours on Project X doing development work yesterday")'),
        },
      },
      async (args: { text: string }) => {
        const client = getClient();
        if (!client) {
          throw new McpError(ErrorCode.InvalidRequest, 'Not authenticated');
        }

        const { text } = args;

        try {
          this.logger.info({ tool: 'log_time', text }, 'Processing log_time request');

          // Parse time entry details
          const { spent_date, hours, isLeave, leaveType } = parseTimeEntry(
            text,
            this.config.standardWorkDayHours,
            this.config.timezone
          );

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
                type: 'text' as const,
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
    );

    // Register list_projects tool
    server.registerTool(
      'list_projects',
      {
        description: 'List available Harvest projects',
      },
      async () => {
        const client = getClient();
        if (!client) {
          throw new McpError(ErrorCode.InvalidRequest, 'Not authenticated');
        }

        this.logger.info({ tool: 'list_projects' }, 'Processing list_projects request');
        const projectAssignments = await client.getProjectAssignments();
        return {
          content: [
            {
              type: 'text' as const,
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
    );

    // Register list_tasks tool
    server.registerTool(
      'list_tasks',
      {
        description: 'List available tasks for a project',
        inputSchema: {
          project_id: z.number().describe('Project ID'),
        },
      },
      async (args: { project_id: number }) => {
        const client = getClient();
        if (!client) {
          throw new McpError(ErrorCode.InvalidRequest, 'Not authenticated');
        }

        const { project_id } = args;
        this.logger.info({ tool: 'list_tasks', project_id }, 'Processing list_tasks request');
        const taskAssignments = await client.getTaskAssignments(project_id);
        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify(taskAssignments.map((t: { task: { id: number; name: string } }) => ({
                id: t.task.id,
                name: t.task.name,
              })), null, 2),
            },
          ],
        };
      }
    );

    // Register list_entries tool
    server.registerTool(
      'list_entries',
      {
        description: 'List recent time entries',
        inputSchema: {
          from: z.string().optional().describe('Start date (YYYY-MM-DD)'),
          to: z.string().optional().describe('End date (YYYY-MM-DD)'),
        },
      },
      async (args: { from?: string; to?: string }) => {
        const client = getClient();
        if (!client) {
          throw new McpError(ErrorCode.InvalidRequest, 'Not authenticated');
        }

        const { from, to } = args;
        this.logger.info({ tool: 'list_entries', from, to }, 'Processing list_entries request');

        const params: { from?: string; to?: string } = {};
        if (from) params.from = from;
        if (to) params.to = to;

        const entries = await client.listTimeEntries(params);
        return {
          content: [
            {
              type: 'text' as const,
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
    );

    // Register get_time_report tool
    server.registerTool(
      'get_time_report',
      {
        description: 'Get time reports using natural language',
        inputSchema: {
          text: z.string().describe('Natural language query (e.g., "Show time report for last month", "Get time summary for Project X")'),
        },
      },
      async (args: { text: string }) => {
        const client = getClient();
        if (!client) {
          throw new McpError(ErrorCode.InvalidRequest, 'Not authenticated');
        }

        const { text } = args;

        try {
          this.logger.info({ tool: 'get_time_report', text }, 'Processing get_time_report request');

          const { from, to } = parseDateRange(text, this.config.timezone);
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
                type: 'text' as const,
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
    );
  }
}
