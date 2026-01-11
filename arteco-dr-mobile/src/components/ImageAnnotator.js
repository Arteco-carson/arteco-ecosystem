import React, { useState } from 'react';
import { View, StyleSheet, Dimensions, Button } from 'react-native';
import { Canvas, Path, Image, useImage, useTouchHandler } from '@shopify/react-native-skia';

export const ImageAnnotator = ({ imageUrl, onSave, onCancel, initialPaths = [] }) => {
  const image = useImage(imageUrl);
  const [paths, setPaths] = useState(initialPaths);
  const [currentPath, setCurrentPath] = useState("");
  
  const touchHandler = useTouchHandler({
    onStart: ({ x, y }) => {
      setCurrentPath(`M ${x} ${y}`);
    },
    onActive: ({ x, y }) => {
      setCurrentPath((prev) => `${prev} L ${x} ${y}`);
    },
    onEnd: () => {
      if (currentPath) {
        setPaths((prev) => [
          ...prev,
          { path: currentPath, color: "red", strokeWidth: 4 },
        ]);
        setCurrentPath("");
      }
    },
  });

  if (!image) {
    return <View style={styles.container} />;
  }

  const { width, height } = Dimensions.get('window');

  return (
    <View style={styles.container}>
      <Canvas style={{ width, height }} onTouch={touchHandler}>
        <Image image={image} x={0} y={0} width={width} height={height} fit="contain" />
        
        {paths.map((p, index) => (
          <Path
            key={index}
            path={p.path}
            color={p.color}
            style="stroke"
            strokeWidth={p.strokeWidth}
          />
        ))}
        
        {currentPath !== "" && (
          <Path
            path={currentPath}
            color="red"
            style="stroke"
            strokeWidth={4}
          />
        )}
      </Canvas>
      
      <View style={styles.controls}>
        <Button title="Cancel" onPress={onCancel} color="#FF3B30" />
        <Button title="Undo" onPress={() => setPaths(paths.slice(0, -1))} />
        <Button title="Save Annotation" onPress={() => onSave(paths)} />
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: 'black' },
  controls: { flexDirection: 'row', justifyContent: 'space-around', padding: 20, backgroundColor: 'white' }
});