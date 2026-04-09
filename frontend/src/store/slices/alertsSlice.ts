import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import type { PayloadAction } from '@reduxjs/toolkit';
import { alertsService } from '../../services/api';
import type { AlertRule, AlertHistory } from '../../types';

interface AlertsState {
  rules: AlertRule[];
  history: AlertHistory[];
  loading: boolean;
  error: string | null;
}

const initialState: AlertsState = {
  rules: [],
  history: [],
  loading: false,
  error: null,
};

export const fetchAlertRules = createAsyncThunk('alerts/fetchAlertRules', async () => {
  const data = await alertsService.getAlertRules();
  return data;
});

export const createAlertRule = createAsyncThunk('alerts/createAlertRule', async (rule: Omit<AlertRule, 'id' | 'created_at' | 'updated_at'>) => {
  const data = await alertsService.createAlertRule(rule);
  return data;
});

export const fetchAlertHistory = createAsyncThunk('alerts/fetchAlertHistory', async () => {
  const data = await alertsService.getAlertHistory();
  return data;
});

const alertsSlice = createSlice({
  name: 'alerts',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    // Handle fetchAlertRules
    builder
      .addCase(fetchAlertRules.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAlertRules.fulfilled, (state, action: PayloadAction<AlertRule[]>) => {
        state.loading = false;
        state.rules = action.payload;
      })
      .addCase(fetchAlertRules.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch alert rules';
      });
    
    // Handle createAlertRule
    builder
      .addCase(createAlertRule.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(createAlertRule.fulfilled, (state, action: PayloadAction<AlertRule>) => {
        state.loading = false;
        state.rules.push(action.payload);
      })
      .addCase(createAlertRule.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to create alert rule';
      });
    
    // Handle fetchAlertHistory
    builder
      .addCase(fetchAlertHistory.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAlertHistory.fulfilled, (state, action: PayloadAction<AlertHistory[]>) => {
        state.loading = false;
        state.history = action.payload;
      })
      .addCase(fetchAlertHistory.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch alert history';
      });
  },
});

export default alertsSlice.reducer;
