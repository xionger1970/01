import { configureStore, combineReducers } from '@reduxjs/toolkit';
import dashboardReducer from './slices/dashboardSlice';
import attackEventsReducer from './slices/attackEventsSlice';
import alertsReducer from './slices/alertsSlice';
import configurationsReducer from './slices/configurationsSlice';

// 组合reducers
const rootReducer = combineReducers({
  dashboard: dashboardReducer,
  attackEvents: attackEventsReducer,
  alerts: alertsReducer,
  configurations: configurationsReducer,
});

const store = configureStore({
  reducer: rootReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false,
    }),
});

// 暂时不使用persistor
export const persistor = {
  flush: () => {},
  pause: () => {},
  persist: () => {},
  purge: () => {},
  rehydrate: () => {},
  subscribe: () => () => {},
};

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export default store;
