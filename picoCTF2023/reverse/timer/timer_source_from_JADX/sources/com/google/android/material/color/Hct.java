package com.google.android.material.color;

final class Hct {
    private static final float CHROMA_SEARCH_ENDPOINT = 0.4f;
    private static final float DE_MAX = 1.0f;
    private static final float DE_MAX_ERROR = 1.0E-9f;
    private static final float DL_MAX = 0.2f;
    private static final float LIGHTNESS_SEARCH_ENDPOINT = 0.01f;
    private float chroma;
    private float hue;
    private float tone;

    public static Hct from(float hue2, float chroma2, float tone2) {
        return new Hct(hue2, chroma2, tone2);
    }

    public static Hct fromInt(int argb) {
        Cam16 cam = Cam16.fromInt(argb);
        return new Hct(cam.getHue(), cam.getChroma(), ColorUtils.lstarFromInt(argb));
    }

    private Hct(float hue2, float chroma2, float tone2) {
        setInternalState(gamutMap(hue2, chroma2, tone2));
    }

    public float getHue() {
        return this.hue;
    }

    public float getChroma() {
        return this.chroma;
    }

    public float getTone() {
        return this.tone;
    }

    public int toInt() {
        return gamutMap(this.hue, this.chroma, this.tone);
    }

    public void setHue(float newHue) {
        setInternalState(gamutMap(MathUtils.sanitizeDegrees(newHue), this.chroma, this.tone));
    }

    public void setChroma(float newChroma) {
        setInternalState(gamutMap(this.hue, newChroma, this.tone));
    }

    public void setTone(float newTone) {
        setInternalState(gamutMap(this.hue, this.chroma, newTone));
    }

    private void setInternalState(int argb) {
        Cam16 cam = Cam16.fromInt(argb);
        float tone2 = ColorUtils.lstarFromInt(argb);
        this.hue = cam.getHue();
        this.chroma = cam.getChroma();
        this.tone = tone2;
    }

    private static int gamutMap(float hue2, float chroma2, float tone2) {
        return gamutMapInViewingConditions(hue2, chroma2, tone2, ViewingConditions.DEFAULT);
    }

    static int gamutMapInViewingConditions(float hue2, float chroma2, float tone2, ViewingConditions viewingConditions) {
        if (((double) chroma2) < 1.0d || ((double) Math.round(tone2)) <= 0.0d || ((double) Math.round(tone2)) >= 100.0d) {
            return ColorUtils.intFromLstar(tone2);
        }
        float hue3 = MathUtils.sanitizeDegrees(hue2);
        float high = chroma2;
        float mid = chroma2;
        float low = 0.0f;
        boolean isFirstLoop = true;
        Cam16 answer = null;
        while (Math.abs(low - high) >= CHROMA_SEARCH_ENDPOINT) {
            Cam16 possibleAnswer = findCamByJ(hue3, mid, tone2);
            if (!isFirstLoop) {
                if (possibleAnswer == null) {
                    high = mid;
                } else {
                    answer = possibleAnswer;
                    low = mid;
                }
                mid = low + ((high - low) / 2.0f);
            } else if (possibleAnswer != null) {
                return possibleAnswer.viewed(viewingConditions);
            } else {
                isFirstLoop = false;
                mid = low + ((high - low) / 2.0f);
            }
        }
        if (answer == null) {
            return ColorUtils.intFromLstar(tone2);
        }
        return answer.viewed(viewingConditions);
    }

    private static Cam16 findCamByJ(float hue2, float chroma2, float tone2) {
        float low = 0.0f;
        float high = 100.0f;
        float bestdL = 1000.0f;
        float bestdE = 1000.0f;
        Cam16 bestCam = null;
        while (Math.abs(low - high) > LIGHTNESS_SEARCH_ENDPOINT) {
            float mid = low + ((high - low) / 2.0f);
            int clipped = Cam16.fromJch(mid, chroma2, hue2).getInt();
            float clippedLstar = ColorUtils.lstarFromInt(clipped);
            float dL = Math.abs(tone2 - clippedLstar);
            if (dL < 0.2f) {
                Cam16 camClipped = Cam16.fromInt(clipped);
                float dE = camClipped.distance(Cam16.fromJch(camClipped.getJ(), camClipped.getChroma(), hue2));
                if (dE <= 1.0f && dE <= bestdE) {
                    bestdL = dL;
                    bestdE = dE;
                    bestCam = camClipped;
                }
            }
            if (bestdL == 0.0f && bestdE < DE_MAX_ERROR) {
                break;
            } else if (clippedLstar < tone2) {
                low = mid;
            } else {
                high = mid;
            }
        }
        return bestCam;
    }
}
