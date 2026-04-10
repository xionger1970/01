import { configureStore, combineReducers } from '@reduxjs/toolkit';
import { persistStore, persistReducer } from 'redux-persist';
import storage from 'redux-persist/lib/storage';
import dashboardReducer from './slices/dashboardSlice';
import attackEventsReducer from './slices/attackEventsSlice';
import alertsReducer from './slices/alertsSlice';
import configurationsReducer from './slices/configurationsSlice';

// 配置持久化
const persistConfig = {
  key: 'root',
  storage,
  whitelist: ['configurations'], // 只持久化配置
  blacklist: ['dashboard', 'attackEvents', 'alerts'], // 不持久化实时数据
};

// 组合reducers
const rootReducer = combineReducers({
  dashboard: dashboardReducer,
  attackEvents: attackEventsReducer,
  alerts: alertsReducer,
  configurations: configurationsReducer,
});

// 创建持久化reducer
const persistedReducer = persistReducer(persistConfig, rootReducer);

const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // 忽略redux-persist的action
        ignoredActions: ['persist/PERSIST', 'persist/REHYDRATE'],
      },
    }),
});

// 创建持久化store
export const persistor = persistStore(store);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export default store;
