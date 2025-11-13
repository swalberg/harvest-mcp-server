/**
 * Harvest API client with OAuth token support
 */
import axios, { AxiosInstance } from 'axios';
import { Logger } from './logger.js';

export interface HarvestTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

export interface HarvestUser {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
}

export class HarvestClient {
  private axiosInstance: AxiosInstance;
  private logger: Logger;

  constructor(accessToken: string, accountId: string, logger: Logger) {
    this.logger = logger;
    this.axiosInstance = axios.create({
      baseURL: 'https://api.harvestapp.com/v2',
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Harvest-Account-Id': accountId,
        'User-Agent': 'Harvest MCP Server (oauth@example.com)',
      },
    });

    // Add response interceptor for logging
    this.axiosInstance.interceptors.response.use(
      (response) => {
        this.logger.debug(
          { url: response.config.url, status: response.status },
          'Harvest API request successful'
        );
        return response;
      },
      (error) => {
        this.logger.error(
          {
            url: error.config?.url,
            status: error.response?.status,
            message: error.response?.data?.message || error.message,
          },
          'Harvest API request failed'
        );
        throw error;
      }
    );
  }

  async getCurrentUser(): Promise<HarvestUser> {
    const response = await this.axiosInstance.get('/users/me');
    return response.data;
  }

  async getProjectAssignments() {
    const response = await this.axiosInstance.get('/users/me/project_assignments');
    return response.data.project_assignments;
  }

  async getTaskAssignments(projectId: number) {
    const response = await this.axiosInstance.get(`/projects/${projectId}/task_assignments`);
    return response.data.task_assignments;
  }

  async createTimeEntry(data: {
    project_id: number;
    task_id: number;
    spent_date: string;
    hours: number;
    notes: string;
  }) {
    const response = await this.axiosInstance.post('/time_entries', data);
    return response.data;
  }

  async listTimeEntries(params?: { from?: string; to?: string }) {
    const response = await this.axiosInstance.get('/time_entries', { params });
    return response.data.time_entries;
  }

  async getTimeReport(endpoint: string, params: { from: string; to: string }) {
    const response = await this.axiosInstance.get(endpoint, { params });
    return response.data;
  }

  getAxiosInstance(): AxiosInstance {
    return this.axiosInstance;
  }
}
