import React, { useEffect, useContext } from 'react';
import { 
  View, 
  Text, 
  StyleSheet, 
  TouchableOpacity, 
  SafeAreaView, 
  ScrollView, 
  Alert 
} from 'react-native';
import { AuthContext } from '../context/AuthContext';
import { Image as ImageIcon, FileText, ChevronRight, LogOut, Layers, Palette } from 'lucide-react-native';

const HomeScreen = ({ navigation }) => {
  const { userToken, signOut } = useContext(AuthContext);

  // --- SESSION VALIDATION ---
  useEffect(() => {
    // If the token is missing or explicitly invalid, redirect to Login
    if (!userToken) {
      handleSessionExpired();
    }
    
    // Optional: You could add an API 'ping' here to verify the token 
    // is still valid on the UK Management server.
  }, [userToken]);

  const handleSessionExpired = () => {
    Alert.alert("Session Expired", "For security compliance, please log in again.");
    signOut(); // This should clear the token and trigger the AuthNavigator switch
  };

  const NavCard = ({ title, subtitle, icon: Icon, onPress }) => (
    <TouchableOpacity style={styles.card} onPress={onPress}>
      <View style={styles.cardIconContainer}>
        <Icon color="#2c3e50" size={28} />
      </View>
      <View style={styles.cardTextContainer}>
        <Text style={styles.cardTitle}>{title}</Text>
        <Text style={styles.cardSubtitle}>{subtitle}</Text>
      </View>
      <ChevronRight color="#cbd5e1" size={20} />
    </TouchableOpacity>
  );

  return (
    <SafeAreaView style={styles.container}>
      {/* HEADER SECTION */}
      <View style={styles.header}>
        <View>
          <Text style={styles.welcomeText}>Arteco System</Text>
          <Text style={styles.dateText}>Collection Manager Portal</Text>
        </View>
      </View>

      <ScrollView contentContainerStyle={styles.menuContainer}>
        <Text style={styles.sectionTitle}>Management Modules</Text>
        
        <NavCard 
          title="Collections" 
          subtitle="Organize artworks into groups" 
          icon={Layers}
          onPress={() => navigation.navigate('CollectionsScreen')} 
        />

        <NavCard 
          title="Artworks" 
          subtitle="Manage collection inventory" 
          icon={ImageIcon}
          onPress={() => navigation.navigate('ArtworkList')} 
        />

        <NavCard 
          title="Artists" 
          subtitle="Manage artist profiles" 
          icon={Palette}
          onPress={() => navigation.navigate('ArtistListScreen')} 
        />

        <NavCard 
          title="Appraisals" 
          subtitle="Review valuation reports" 
          icon={FileText}
          onPress={() => navigation.navigate('AppraisalListScreen')} 
        />

        {/* LOGOUT OPTION */}
        <TouchableOpacity style={styles.logoutButton} onPress={() => signOut()}>
          <LogOut color="#e11d48" size={20} />
          <Text style={styles.logoutText}>Sign Out of System</Text>
        </TouchableOpacity>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f8fafc' },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 25,
    paddingVertical: 20,
    backgroundColor: '#246A73',
    borderBottomWidth: 1,
    borderBottomColor: '#e2e8f0',
  },
  welcomeText: { fontSize: 20, fontWeight: 'bold', color: '#ffffff' },
  dateText: { fontSize: 14, color: '#e2e8f0' },
  menuContainer: { padding: 25 },
  sectionTitle: { 
    fontSize: 14, 
    fontWeight: '700', 
    color: '#94a3b8', 
    textTransform: 'uppercase', 
    letterSpacing: 1,
    marginBottom: 20 
  },
  card: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#fff',
    padding: 20,
    borderRadius: 16,
    marginBottom: 15,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 15,
    elevation: 2,
  },
  cardIconContainer: {
    width: 50,
    height: 50,
    backgroundColor: '#f1f5f9',
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
    marginRight: 15,
  },
  cardTextContainer: { flex: 1 },
  cardTitle: { fontSize: 16, fontWeight: 'bold', color: '#1e293b' },
  cardSubtitle: { fontSize: 13, color: '#64748b', marginTop: 2 },
  logoutButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 40,
    padding: 15,
    gap: 10
  },
  logoutText: { color: '#e11d48', fontWeight: 'bold', fontSize: 15 }
});

export default HomeScreen;