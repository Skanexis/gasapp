package org.aegis.app.components

import android.content.Context
import android.util.AttributeSet
import android.widget.EditText
import androidx.annotation.DrawableRes
import androidx.core.content.ContextCompat

/**
 * AEGIS TextField component with visual states:
 * 1. Normal
 * 2. Focused
 * 3. Disabled
 * 4. Error
 */
class AegisTextField @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : EditText(context, attrs, defStyleAttr) {

    // State tracking
    private var isError = false
    private var errorText: CharSequence? = null

    // Drawable resources for different states
    private var normalBackground: Int = 0
    private var focusedBackground: Int = 0
    private var disabledBackground: Int = 0
    private var errorBackground: Int = 0

    init {
        // Initialize with default background
        updateBackgroundForState()
    }

    /**
     * Set background resources for different states
     */
    fun setStateBackgrounds(
        @DrawableRes normal: Int,
        @DrawableRes focused: Int,
        @DrawableRes disabled: Int,
        @DrawableRes error: Int
    ) {
        normalBackground = normal
        focusedBackground = focused
        disabledBackground = disabled
        errorBackground = error
        updateBackgroundForState()
    }

    /**
     * Show error state with optional error message
     */
    fun showError(errorMessage: CharSequence? = null) {
        isError = true
        errorText = errorMessage
        // In a full implementation, we might show the error below the field
        updateBackgroundForState()
        // Optional: shake animation or other visual feedback
    }

    /**
     * Clear error state
     */
    fun clearError() {
        isError = false
        errorText = null
        updateBackgroundForState()
    }

    /**
     * Update background based on current state
     */
    private fun updateBackgroundForState() {
        val background = when {
            isNotEnabled -> disabledBackground
            isError -> errorBackground
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

    override fun setFocused(focused: Boolean) {
        super.setFocused(focused)
        updateBackgroundForState()
    }

    /**
     * Get error message if currently in error state
     */
    fun getError(): CharSequence? {
        return if (isError) errorText else null
    }

    /**
     * Check if field is in error state
     */
    fun isInErrorState(): Boolean {
        return isError
    }
}