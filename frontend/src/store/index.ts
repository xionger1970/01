import { configureStore } from '@reduxjs/toolkit';
import dashboardReducer from './slices/dashboardSlice';
import attackEventsReducer from './slices/attackEventsSlice';
import alertsReducer from './slices/alertsSlice';
import configurationsReducer from './slices/configurationsSlice';

const store = configureStore({
  reducer: {
    dashboard: dashboardReducer,
    attackEvents: attackEventsReducer,
    alerts: alertsReducer,
    configurations: configurationsReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export default store;
