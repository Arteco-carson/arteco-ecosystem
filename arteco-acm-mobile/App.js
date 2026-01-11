import React, { useContext } from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { View, ActivityIndicator, StyleSheet } from 'react-native';
import { 
  Palette, 
  User, 
  FileText,
  Home,
  Layers
} from 'lucide-react-native';

// --- CORE IMPORTS ---
import { AuthProvider, AuthContext } from './src/context/AuthContext';
import LoginScreen from './src/screens/LoginScreen';
import RegisterScreen from './src/screens/RegisterScreen';
import HomeScreen from './src/screens/HomeScreen';
import CollectionsScreen from './src/screens/CollectionsScreen';
import CreateCollectionScreen from './src/screens/CreateCollectionScreen';
import ArtworkDetailsScreen from './src/screens/ArtworkDetailsScreen';
import ArtistListScreen from './src/screens/ArtistListScreen';
import ArtistDetailsScreen from './src/screens/ArtistDetailsScreen';

// --- MANAGEMENT SCREENS ---
import ArtworkListScreen from './src/screens/ArtworkListScreen';
import AppraisalListScreen from './src/screens/AppraisalListScreen';
import AddAppraisalScreen from './src/screens/AddAppraisalScreen';
import ProfileScreen from './src/screens/ProfileScreen';

const Placeholder = () => (
  <View style={styles.center}>
    <ActivityIndicator size="small" color="#2c3e50" />
  </View>
);

const Stack = createStackNavigator();
const Tab = createBottomTabNavigator();

// --- 1. SUB-STACKS ---
const ArtworkStack = () => (
  <Stack.Navigator screenOptions={{ headerShown: false }}>
    <Stack.Screen name="ArtworkList" component={ArtworkListScreen} />
    <Stack.Screen name="ArtworkDetail" component={ArtworkDetailsScreen} />
    <Stack.Screen name="AddAppraisal" component={AddAppraisalScreen} />
  </Stack.Navigator>
);

const AppraisalStack = () => (
  <Stack.Navigator screenOptions={{ headerShown: false }}>
    <Stack.Screen name="AppraisalList" component={AppraisalListScreen} />
    <Stack.Screen name="AddAppraisal" component={AddAppraisalScreen} />
  </Stack.Navigator>
);

const CollectionStack = () => (
  <Stack.Navigator screenOptions={{ headerShown: false }}>
    <Stack.Screen name="CollectionsScreen" component={CollectionsScreen} />
    <Stack.Screen name="CreateCollection" component={CreateCollectionScreen} />
    <Stack.Screen name="ArtworkDetail" component={ArtworkDetailsScreen} />
    <Stack.Screen name="AddAppraisal" component={AddAppraisalScreen} />
  </Stack.Navigator>
);

// --- DASHBOARD STACK ---
const DashboardStack = () => (
  <Stack.Navigator screenOptions={{ headerShown: false }}>
    <Stack.Screen name="Home" component={HomeScreen} />
    <Stack.Screen name="ArtistListScreen" component={ArtistListScreen} />
    <Stack.Screen name="ArtistDetail" component={ArtistDetailsScreen} />
    <Stack.Screen name="ArtworkDetail" component={ArtworkDetailsScreen} />
    <Stack.Screen name="CollectionsScreen" component={CollectionsScreen} />
    <Stack.Screen name="CreateCollection" component={CreateCollectionScreen} />
    <Stack.Screen name="AppraisalListScreen" component={AppraisalListScreen} />
    <Stack.Screen name="AddAppraisal" component={AddAppraisalScreen} />
  </Stack.Navigator>
);

// --- 2. MAIN TAB NAVIGATOR ---
function MainTabNavigator() {
  return (
    <Tab.Navigator 
      screenOptions={{ 
        headerShown: false,
        tabBarActiveTintColor: '#ffffff',
        tabBarInactiveTintColor: '#cbd5e1',
        tabBarStyle: { backgroundColor: '#246A73' }
      }}
    >
      <Tab.Screen 
        name="Dashboard" 
        component={DashboardStack} 
        options={{ tabBarIcon: ({color}) => <Home color={color} size={24} /> }} 
      />
      <Tab.Screen 
        name="Collections" 
        component={CollectionStack} 
        options={{ tabBarIcon: ({color}) => <Layers color={color} size={24} /> }} 
      />
      <Tab.Screen 
        name="ArtworkList" 
        component={ArtworkStack} 
        options={{ tabBarIcon: ({color}) => <Palette color={color} size={24} /> }} 
      />
      <Tab.Screen 
        name="Appraisals" 
        component={AppraisalStack} 
        options={{ tabBarIcon: ({color}) => <FileText color={color} size={24} /> }} 
      />
      <Tab.Screen 
        name="Profile" 
        component={ProfileScreen} 
        options={{ tabBarIcon: ({color}) => <User color={color} size={24} /> }} 
      />
    </Tab.Navigator>
  );
}

// --- 3. THE NAVIGATOR GATEKEEPER ---
function AppNavigator() {
  const auth = useContext(AuthContext);

  if (!auth || auth.isLoading) {
    return (
      <View style={styles.center}>
        <ActivityIndicator size="large" color="#2c3e50" />
      </View>
    );
  }

  return (
    <NavigationContainer>
      <Stack.Navigator screenOptions={{ headerShown: false }}>
        {auth.userToken == null ? (
          <>
            <Stack.Screen name="Login" component={LoginScreen} />
            <Stack.Screen name="Register" component={RegisterScreen} />
          </>
        ) : (
          <>
            <Stack.Screen name="Main" component={MainTabNavigator} />
          </>
        )}
      </Stack.Navigator>
    </NavigationContainer>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppNavigator />
    </AuthProvider>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', backgroundColor: '#f8fafc' }
});