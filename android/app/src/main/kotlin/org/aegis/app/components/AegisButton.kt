package org.aegis.app.components

import android.content.Context
import android.util.AttributeSet
import android.widget.Button
import androidx.annotation.DrawableRes
import androidx.core.content.ContextCompat

/**
 * AEGIS Button component with 7 states:
 * 1. Normal
 * 2. Pressed
 * 3. Hovered (not typically used on mobile, but kept for completeness)
 * 4. Focused
 * 5. Disabled
 * 6. Loading
 * 7. Error
 */
class AegisButton @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : Button(context, attrs, defStyleAttr) {

    // State tracking
    private var isLoading = false
    private var isError = false
    private var originalText: CharSequence? = null

    // Drawable resources for different states (would be defined in XML)
    private var normalBackground: Int = 0
    private var pressedBackground: Int = 0
    private var focusedBackground: Int = 0
    private var disabledBackground: Int = 0
    private var loadingBackground: Int = 0
    private var errorBackground: Int = 0

    init {
        // Initialize with default background
        updateBackgroundForState()
    }

    /**
     * Set background resources for different states
     * These would typically be set via XML or theme attributes
     */
    fun setStateBackgrounds(
        @DrawableRes normal: Int,
        @DrawableRes pressed: Int,
        @DrawableRes focused: Int,
        @DrawableRes disabled: Int,
        @DrawableRes loading: Int,
        @DrawableRes error: Int
    ) {
        normalBackground = normal
        pressedBackground = pressed
        focusedBackground = focused
        disabledBackground = disabled
        loadingBackground = loading
        errorBackground = error
        updateBackgroundForState()
    }

    /**
     * Show loading state
     */
    fun showLoading() {
        isLoading = true
        isError = false
        originalText = text
        text = context.getString(org.aegis.app.R.string.button_loading)
        isEnabled = false
        updateBackgroundForState()
    }

    /**
     * Hide loading state and return to normal
     */
    fun hideLoading() {
        isLoading = false
        text = originalText
        isEnabled = true
        updateBackgroundForState()
    }

    /**
     * Show error state
     */
    fun showError(errorText: CharSequence? = null) {
        isLoading = false
        isError = true
        originalText = text
        text = errorText ?: context.getString(org.aegis.app.R.string.button_error)
        isEnabled = true
        updateBackgroundForState()
    }

    /**
     * Return to normal state from error
     */
    fun hideError() {
        isError = false
        text = originalText
        updateBackgroundForState()
    }

    /**
     * Update background based on current state
     */
    private fun updateBackgroundForState() {
        val background = when {
            isNotEnabled -> disabledBackground
            isLoading -> loadingBackground
            isError -> errorBackground
            isPressed -> pressedBackground
            isFocused -> focusedBackground
            else -> normalBackground
        }

        if (background != 0) {
            setBackgroundResource(background)
        }
    }

    // Override state change methods to update background
    override fun setEnabled(enabled: Boolean) {
        super.setEnabled(enabled)
        updateBackgroundForState()
    }

    override fun setPressed(pressed: Boolean) {
        super.setPressed(pressed)
        updateBackgroundForState()
    }

    override fun setFocused(focused: Boolean) {
        super.setFocused(focused)
        updateBackgroundForState()
    }

    companion object {
        // Helper constants for state identification
        const val STATE_NORMAL = 0
        const val STATE_PRESSED = 1
        const val STATE_HOVERED = 2
        const val STATE_FOCUSED = 3
        const val STATE_DISABLED = 4
        const val STATE_LOADING = 5
        const val STATE_ERROR = 6
    }
}