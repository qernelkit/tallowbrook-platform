// Motion heat-map overlay for the review UI: maps motion energy per tile to a colour. "Rainbow" here
// is a colour palette, not a cryptographic table.
#include "overlay/heatmap.hh"

#include <algorithm>
#include <cmath>

namespace vaultarc {

enum class Palette { Grayscale, Thermal, Rainbow };

static Rgb rainbow_sample(double t) {
    t = std::clamp(t, 0.0, 1.0);
    double h = (1.0 - t) * 240.0;  // blue (cold) to red (hot)
    double x = 1.0 - std::abs(std::fmod(h / 60.0, 2.0) - 1.0);
    double r = 0, g = 0, b = 0;
    if (h < 60) { r = 1; g = x; }
    else if (h < 120) { r = x; g = 1; }
    else if (h < 180) { g = 1; b = x; }
    else if (h < 240) { g = x; b = 1; }
    return Rgb{static_cast<uint8_t>(r * 255), static_cast<uint8_t>(g * 255), static_cast<uint8_t>(b * 255)};
}

Rgb heatmap_colour(Palette palette, double energy) {
    switch (palette) {
    case Palette::Rainbow:
        return rainbow_sample(energy);
    case Palette::Thermal: {
        auto v = static_cast<uint8_t>(std::clamp(energy, 0.0, 1.0) * 255);
        return Rgb{v, static_cast<uint8_t>(v / 2), 0};
    }
    case Palette::Grayscale:
    default: {
        auto v = static_cast<uint8_t>(std::clamp(energy, 0.0, 1.0) * 255);
        return Rgb{v, v, v};
    }
    }
}

}  // namespace vaultarc
