import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import type { PayloadAction } from '@reduxjs/toolkit';
import { dashboardService } from '../../services/api';
import type { DashboardOverview, TopTarget, SystemStatus, DashboardConfiguration } from '../../types';

interface DashboardState {
  overview: DashboardOverview | null;
  topTargets: TopTarget[];
  systemStatus: SystemStatus | null;
  configuration: DashboardConfiguration;
  loading: boolean;
  error: string | null;
}

const initialState: DashboardState = {
  overview: null,
  topTargets: [],
  systemStatus: null,
  configuration: {
    widgets: [
      {
        id: 'summary',
        type: 'summary',
        title: 'Summary Stats',
        x: 0,
        y: 0,
        width: 24,
        height: 6,
        visible: true,
      },
      {
        id: 'trend',
        type: 'trend',
        title: 'Attack Trend',
        x: 0,
        y: 6,
        width: 16,
        height: 8,
        visible: true,
      },
      {
        id: 'severity',
        type: 'severity',
        title: 'Severity Distribution',
        x: 16,
        y: 6,
        width: 8,
        height: 8,
        visible: true,
      },
      {
        id: 'targets',
        type: 'targets',
        title: 'Top Targets',
        x: 0,
        y: 14,
        width: 12,
        height: 8,
        visible: true,
      },
      {
        id: 'system',
        type: 'system',
        title: 'System Status',
        x: 12,
        y: 14,
        width: 12,
        height: 8,
        visible: true,
      },
    ],
    layout: 'grid',
    theme: 'light',
  },
  loading: false,
  error: null,
};

export const fetchOverview = createAsyncThunk('dashboard/fetchOverview', async () => {
  const data = await dashboardService.getOverview();
  return data;
});

export const fetchTopTargets = createAsyncThunk('dashboard/fetchTopTargets', async () => {
  const data = await dashboardService.getTopTargets();
  return data;
});

export const fetchSystemStatus = createAsyncThunk('dashboard/fetchSystemStatus', async () => {
  const data = await dashboardService.getSystemStatus();
  return data;
});

const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {
    updateWidgetPosition: (state, action: PayloadAction<{ id: string; x: number; y: number }>) => {
      const widget = state.configuration.widgets.find(w => w.id === action.payload.id);
      if (widget) {
        widget.x = action.payload.x;
        widget.y = action.payload.y;
      }
    },
    updateWidgetSize: (state, action: PayloadAction<{ id: string; width: number; height: number }>) => {
      const widget = state.configuration.widgets.find(w => w.id === action.payload.id);
      if (widget) {
        widget.width = action.payload.width;
        widget.height = action.payload.height;
      }
    },
    toggleWidgetVisibility: (state, action: PayloadAction<string>) => {
      const widget = state.configuration.widgets.find(w => w.id === action.payload);
      if (widget) {
        widget.visible = !widget.visible;
      }
    },
    updateLayout: (state, action: PayloadAction<'grid' | 'custom'>) => {
      state.configuration.layout = action.payload;
    },
    updateTheme: (state, action: PayloadAction<'light' | 'dark'>) => {
      state.configuration.theme = action.payload;
    },
    resetDashboard: (state) => {
      state.configuration = initialState.configuration;
    },
  },
  extraReducers: (builder) => {
    // Handle fetchOverview
    builder
      .addCase(fetchOverview.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchOverview.fulfilled, (state, action: PayloadAction<DashboardOverview>) => {
        state.loading = false;
        state.overview = action.payload;
      })
      .addCase(fetchOverview.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch dashboard overview';
      });
    
    // Handle fetchTopTargets
    builder
      .addCase(fetchTopTargets.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchTopTargets.fulfilled, (state, action: PayloadAction<TopTarget[]>) => {
        state.loading = false;
        state.topTargets = action.payload;
      })
      .addCase(fetchTopTargets.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch top targets';
      });
    
    // Handle fetchSystemStatus
    builder
      .addCase(fetchSystemStatus.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchSystemStatus.fulfilled, (state, action: PayloadAction<SystemStatus>) => {
        state.loading = false;
        state.systemStatus = action.payload;
      })
      .addCase(fetchSystemStatus.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch system status';
      });
  },
});

export const { updateWidgetPosition, updateWidgetSize, toggleWidgetVisibility, updateLayout, updateTheme, resetDashboard } = dashboardSlice.actions;

export default dashboardSlice.reducer;
