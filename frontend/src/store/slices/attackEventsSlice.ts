import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import type { PayloadAction } from '@reduxjs/toolkit';
import { attackEventsService } from '../../services/api';
import type { AttackEvent } from '../../types';

interface AttackEventsState {
  events: AttackEvent[];
  stats: any;
  loading: boolean;
  error: string | null;
  filters: {
    attack_type?: string;
    source_ip?: string;
  };
}

const initialState: AttackEventsState = {
  events: [],
  stats: null,
  loading: false,
  error: null,
  filters: {},
};

export const fetchAttackEvents = createAsyncThunk('attackEvents/fetchAttackEvents', async (filters: { attack_type?: string; source_ip?: string; limit?: number }) => {
  const data = await attackEventsService.getAttackEvents(filters.attack_type, filters.source_ip, filters.limit);
  return data;
});

export const fetchAttackStats = createAsyncThunk('attackEvents/fetchAttackStats', async () => {
  const data = await attackEventsService.getAttackStats();
  return data;
});

const attackEventsSlice = createSlice({
  name: 'attackEvents',
  initialState,
  reducers: {
    setFilters: (state, action: PayloadAction<{ attack_type?: string; source_ip?: string }>) => {
      state.filters = action.payload;
    },
  },
  extraReducers: (builder) => {
    // Handle fetchAttackEvents
    builder
      .addCase(fetchAttackEvents.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAttackEvents.fulfilled, (state, action: PayloadAction<AttackEvent[]>) => {
        state.loading = false;
        state.events = action.payload;
      })
      .addCase(fetchAttackEvents.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch attack events';
      });
    
    // Handle fetchAttackStats
    builder
      .addCase(fetchAttackStats.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchAttackStats.fulfilled, (state, action) => {
        state.loading = false;
        state.stats = action.payload;
      })
      .addCase(fetchAttackStats.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch attack stats';
      });
  },
});

export const { setFilters } = attackEventsSlice.actions;
export default attackEventsSlice.reducer;
