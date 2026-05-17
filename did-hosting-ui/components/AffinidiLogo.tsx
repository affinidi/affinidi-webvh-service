import React from "react";
import { View, StyleSheet } from "react-native";

const LOGO_PATH =
  "M386.4 84.6c-.5-2.1-1.1-4.1-1.8-6.1-3-8.8-7.9-15.7-14.9-20.9s-16.4-7.8-28.2-7.8c-10.7 0-20.3 2.5-28.9 7.3s-15.4 11.7-20.5 20.4c-5 8.7-7.6 18.8-7.6 30.3 0 11.6 2.5 21.2 7.5 29.9s11.6 15.5 20 20.4 17.6 7.3 27.7 7.3c9.2 0 16.9-1.8 23.2-5.4s11.3-8.3 15.1-14.1 6.6-12 8.3-18.8v36.2h24.9v-110h-24.9zm-4.6 42.4c-3 5.6-7.5 10-13.3 13.2-5.9 3.2-12.9 4.8-21.2 4.8-7.3 0-13.7-1.6-19.4-4.7-5.6-3.1-10-7.5-13.2-13.1s-4.8-12.1-4.8-19.3c0-11.1 3.3-20.2 9.8-27.1 6.5-7 15.7-10.4 27.6-10.4 8.3 0 15.3 1.5 21.1 4.6s10.2 7.3 13.3 12.9 4.7 12.3 4.7 20.1c0 7-1.6 13.3-4.6 19M553.1 15.4c-6.2 2.7-10.8 7.3-14 12.9s-4.8 11.9-4.8 20.8v4.3h-55.1v-1.5c0-5.2.9-9.2 2.6-11.9s4.1-4.2 7.2-5.3 6.7-1.5 10.7-1.4h14v-22h-18.5c-8.4 0-15.8 1.3-21.9 4s-10.8 6.8-14 12.5c-3.2 5.6-4.8 12.9-4.8 21.8v3.7h-21.8v20.3h21.8v89.6h24.7V73.6h55.1v89.6H559V73.6h34.2V53.3H559v-2c0-5.2.8-8.2 2.6-11 1.7-2.8 4.1-4.7 7.2-5.8 3.1-1 6.7-1.5 10.7-1.3h13.8V11.3h-18c-8.6 0-16 1.4-22.2 4.1M639.6 11.3h-24.9v21.9h24.9zM639.6 53.2h-24.9v110h24.9zM764.2 60.7c-3.9-3.6-8.6-6.3-14-8.1q-8.1-2.7-17.7-2.7c-6.8 0-13 1.1-18.7 3.3-5.6 2.2-10.5 5.3-14.7 9.2-4.1 3.9-7.5 8.4-10 13.3q-2.1 4.05-3.3 8.4v-31h-24.7v110h24.7v-66q1.65-5.1 5.1-9.6c3.7-4.8 8.5-8.8 14.3-11.8s12.3-4.6 19.5-4.6c9.3 0 16.2 2.2 20.6 6.6q6.6 6.6 6.6 20.1v65.3h24.7V93c0-7.3-1.1-13.6-3.2-18.9-2.3-5.3-5.3-9.8-9.2-13.4M822.8 11.3h-24.9v21.8h24.9zM822.8 53.2h-24.9v110h24.9zM946.1 84.8c-1.7-6.8-4.4-12.8-8-17.9-3.7-5.3-8.8-9.4-15.1-12.5-6.4-3-14.2-4.6-23.6-4.6-10.7 0-20.1 2.4-28.4 7.3-8.2 4.9-14.8 11.7-19.6 20.3q-7.2 13.05-7.2 30.3c0 11.6 2.5 21.2 7.3 29.9 4.9 8.7 11.5 15.4 19.9 20.4 8.4 4.9 17.7 7.3 27.9 7.3 9.2 0 16.9-1.8 23.2-5.4s11.3-8.3 15.1-14.1 6.6-12 8.3-18.8v36.099999999999994H971V11.3h-24.9zm-4.5 42.3c-3 5.6-7.5 10-13.3 13.2-5.9 3.2-12.9 4.8-21.2 4.8-7.3 0-13.7-1.6-19.4-4.7-5.6-3.1-10-7.5-13.2-13.1s-4.8-12.1-4.8-19.3c0-11.1 3.3-20.2 9.8-27.2s15.7-10.6 27.6-10.6c8.3 0 15.3 1.6 21.1 4.7s10.2 7.4 13.3 13 4.7 12.3 4.7 20.1c-.1 7.1-1.6 13.4-4.6 19.1M1017.4 11.2h-24.9v22h24.9zM1017.4 53.2h-24.9v110h24.9zM25.2 158.3c17 17.8 41 28.9 67.5 28.9s50.5-11.1 67.5-28.9zM160.2 53.2H8.7C4.4 62.1 1.4 71.9.1 82.1h160.1zM160.2 29.6C143.2 11.8 119.2.7 92.7.7 66.1.7 42.2 11.8 25.2 29.6zM160.2 105.8H.1c1.3 10.2 4.3 20 8.6 28.9h151.5zM176.6 53.2c4.3 8.9 7.3 18.7 8.6 28.9h37.2V53.2zM222.4 158.3h-62.2v28.9h62.2zM176.6 134.7h45.8v-28.9h-37.2c-1.3 10.2-4.2 19.9-8.6 28.9M222.4.6h-62.2v28.9h62.2z";

// Full logo with wordmark: 0 0 1043 188
const FULL_VIEWBOX = "0 0 1043 188";
// Mark only (circle + bars): 0 0 223 188
const MARK_VIEWBOX = "0 0 223 188";

/**
 * Affinidi brand logomark + wordmark.
 *
 * Uses the official Affinidi SVG path data. When `showWordmark` is true
 * the full logo including "affinidi" text is rendered; when false only
 * the brand mark (circle with bars) is shown.
 */
export function AffinidiLogo({
  size = 32,
  showWordmark = true,
}: {
  size?: number;
  showWordmark?: boolean;
}) {
  const viewBox = showWordmark ? FULL_VIEWBOX : MARK_VIEWBOX;
  const aspectRatio = showWordmark ? 1043 / 188 : 223 / 188;
  const width = size * aspectRatio;
  const height = size;

  const encodedPath = LOGO_PATH.replace(/#/g, "%23");
  const svg = [
    `<svg viewBox="${viewBox}" xmlns="http://www.w3.org/2000/svg">`,
    `<path d="${encodedPath}" fill="white"/>`,
    "</svg>",
  ].join("");

  const encoded = `data:image/svg+xml;charset=utf-8,${svg}`;

  return (
    <View style={styles.container}>
      <View style={{ width, height, overflow: "hidden" }}>
        {/* eslint-disable-next-line react-native/no-inline-styles */}
        <img
          src={encoded}
          width={width}
          height={height}
          alt="Affinidi"
          style={{ display: "block" } as any}
        />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flexDirection: "row",
    alignItems: "center",
  },
});
