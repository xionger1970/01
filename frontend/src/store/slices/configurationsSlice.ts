import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import type { PayloadAction } from '@reduxjs/toolkit';
import { configurationsService } from '../../services/api';
import type { Configuration } from '../../types';

interface ConfigurationsState {
  configurations: Configuration[];
  loading: boolean;
  error: string | null;
}

const initialState: ConfigurationsState = {
  configurations: [],
  loading: false,
  error: null,
};

export const fetchConfigurations = createAsyncThunk('configurations/fetchConfigurations', async () => {
  const data = await configurationsService.getConfigurations();
  return data;
});

export const createConfiguration = createAsyncThunk('configurations/createConfiguration', async (config: Omit<Configuration, 'id' | 'created_at' | 'updated_at'>) => {
  const data = await configurationsService.createConfiguration(config);
  return data;
});

export const updateConfiguration = createAsyncThunk('configurations/updateConfiguration', async ({ id, config }: { id: number; config: Omit<Configuration, 'id' | 'created_at' | 'updated_at'> }) => {
  const data = await configurationsService.updateConfiguration(id, config);
  return data;
});

export const deleteConfiguration = createAsyncThunk('configurations/deleteConfiguration', async (id: number) => {
  await configurationsService.deleteConfiguration(id);
  return id;
});

const configurationsSlice = createSlice({
  name: 'configurations',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    // Handle fetchConfigurations
    builder
      .addCase(fetchConfigurations.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchConfigurations.fulfilled, (state, action: PayloadAction<Configuration[]>) => {
        state.loading = false;
        state.configurations = action.payload;
      })
      .addCase(fetchConfigurations.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch configurations';
      });
    
    // Handle createConfiguration
    builder
      .addCase(createConfiguration.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(createConfiguration.fulfilled, (state, action: PayloadAction<Configuration>) => {
        state.loading = false;
        state.configurations.push(action.payload);
      })
      .addCase(createConfiguration.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to create configuration';
      });
    
    // Handle updateConfiguration
    builder
      .addCase(updateConfiguration.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(updateConfiguration.fulfilled, (state, action: PayloadAction<Configuration>) => {
        state.loading = false;
        const index = state.configurations.findIndex(config => config.id === action.payload.id);
        if (index !== -1) {
          state.configurations[index] = action.payload;
        }
      })
      .addCase(updateConfiguration.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to update configuration';
      });
    
    // Handle deleteConfiguration
    builder
      .addCase(deleteConfiguration.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(deleteConfiguration.fulfilled, (state, action: PayloadAction<number>) => {
        state.loading = false;
        state.configurations = state.configurations.filter(config => config.id !== action.payload);
      })
      .addCase(deleteConfiguration.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to delete configuration';
      });
  },
});

export default configurationsSlice.reducer;
