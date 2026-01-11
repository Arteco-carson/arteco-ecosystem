import 'react-native-gesture-handler';
import React, { useContext } from 'react';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { AuthProvider, AuthContext } from './src/context/AuthContext';
import LoginScreen from './src/screens/LoginScreen';
import HomeScreen from './src/screens/HomeScreen';
import CreateDefectReportScreen from './src/screens/CreateDefectReportScreen';
import RetrieveDefectReportScreen from './src/screens/RetrieveDefectReportScreen';
import CaptureAndAnnotateScreen from './src/screens/CaptureAndAnnotateScreen';
import ReportTypeSelectionScreen from './src/screens/ReportTypeSelectionScreen';
import CreateNewObjectScreen from './src/screens/CreateNewObjectScreen';
import { View, ActivityIndicator, Alert } from 'react-native';
import { Home, PlusSquare, Search, LogOut } from 'lucide-react-native';

const Stack = createStackNavigator();
const Tab = createBottomTabNavigator();
const CreateStack = createStackNavigator();
const HomeStack = createStackNavigator();

function CreateReportStackNavigator() {
  return (
    <CreateStack.Navigator screenOptions={{ headerShown: false }}>
      <CreateStack.Screen name="ReportTypeSelection" component={ReportTypeSelectionScreen} />
      <CreateStack.Screen name="CreateNewObject" component={CreateNewObjectScreen} />
      <CreateStack.Screen name="CreateDefectReport" component={CreateDefectReportScreen} />
      <CreateStack.Screen name="CaptureAndAnnotate" component={CaptureAndAnnotateScreen} />
    </CreateStack.Navigator>
  );
}

function HomeStackNavigator() {
  return (
    <HomeStack.Navigator screenOptions={{ headerShown: false }}>
      <HomeStack.Screen name="HomeScreenContent" component={HomeScreen} />
      <HomeStack.Screen name="ReportTypeSelection" component={ReportTypeSelectionScreen} />
      <HomeStack.Screen name="CreateNewObject" component={CreateNewObjectScreen} />
      <HomeStack.Screen name="CaptureAndAnnotate" component={CaptureAndAnnotateScreen} />
    </HomeStack.Navigator>
  );
}

function MainTabs() {
  const { logout } = useContext(AuthContext);

  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarActiveTintColor: '#ffffff',
        tabBarInactiveTintColor: '#cbd5e1',
        tabBarStyle: {
          backgroundColor: '#246A73',
          borderTopWidth: 0,
        },
        tabBarIcon: ({ color, size }) => {
          if (route.name === 'Home') return <Home color={color} size={size} />;
          if (route.name === 'CreateDefectReport') return <PlusSquare color={color} size={size} />;
          if (route.name === 'RetrieveDefectReport') return <Search color={color} size={size} />;
          if (route.name === 'Logout') return <LogOut color={color} size={size} />;
        },
      })}
    >
      <Tab.Screen name="Home" component={HomeStackNavigator} options={{ title: 'Home' }} />
      <Tab.Screen name="CreateDefectReport" component={CreateReportStackNavigator} options={{ title: 'Create Report' }} />
      <Tab.Screen name="RetrieveDefectReport" component={RetrieveDefectReportScreen} options={{ title: 'Search' }} />
      <Tab.Screen 
        name="Logout" 
        component={View} // Dummy component
        listeners={{
          tabPress: (e) => {
            e.preventDefault();
            Alert.alert('Logout', 'Are you sure you want to logout?', [
              { text: 'Cancel', style: 'cancel' },
              { text: 'Logout', style: 'destructive', onPress: logout }
            ]);
          },
        }}
      />
    </Tab.Navigator>
  );
}

const AppNavigator = () => {
  const { userToken, isLoading } = useContext(AuthContext);

  if (isLoading) {
    return (
      <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
        <ActivityIndicator size="large" />
      </View>
    );
  }

  return (
    <NavigationContainer>
      {userToken ? (
        <Stack.Navigator>
          <Stack.Screen name="Main" component={MainTabs} options={{ headerShown: false }} />
        </Stack.Navigator>
      ) : (
        <Stack.Navigator>
          <Stack.Screen 
            name="Login" 
            component={LoginScreen} 
            options={{ headerShown: false }}
          />
        </Stack.Navigator>
      )}
    </NavigationContainer>
  );
};

export default function App() {
  return (
    <SafeAreaProvider>
      <GestureHandlerRootView style={{ flex: 1 }}>
        <AuthProvider>
          <AppNavigator />
        </AuthProvider>
      </GestureHandlerRootView>
    </SafeAreaProvider>
  );
}
