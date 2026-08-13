package org.aegis.app.components

import android.content.Context
import android.util.AttributeSet
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.core.content.ContextCompat

/**
 * AEGIS ListRow component - a reusable row item for lists
 * Can contain text, icons, and secondary information
 */
class AegisListRow @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    private val titleTextView: TextView
    private val subtitleTextView: TextView?
    private val iconView: TextView? // Using TextView for simplicity, would be ImageView in production

    // State tracking
    private var isSelected = false
    private var isActivated = false

    // Drawable resources for different states
    private var normalBackground: Int = 0
    private var selectedBackground: Int = 0
    private var activatedBackground: Int = 0
    private var disabledBackground: Int = 0

    init {
        // Inflate the layout for this custom view
        // For simplicity, we'll create views programmatically
        // In production, this would typically inflate from XML
        orientation = LinearLayout.HORIZONTAL
        setPadding(16, 16, 16, 16)

        // Create icon view (placeholder)
        iconView = TextView(context).apply {
            setTextSize(24f)
            setPadding(0, 0, 12, 0)
            layoutParams = LayoutParams(
                LayoutParams.WRAP_CONTENT,
                LayoutParams.WRAP_CONTENT
            )
            addView(this)
        }

        // Create title text view
        titleTextView = TextView(context).apply {
            textSize = 16f
            setTypeface(null, android.graphics.Typeface.BOLD)
            layoutParams = LayoutParams(
                0,
                LayoutParams.WRAP_CONTENT,
                1.0f
            )
            addView(this)
        }

        // Create subtitle text view (optional)
        subtitleTextView = TextView(context).apply {
            textSize = 14f
            setTextColor(ContextCompat.getColor(context, android.R.color.darker_gray))
            setPadding(0, 4, 0, 0)
            layoutParams = LayoutParams(
                LayoutParams.WRAP_CONTENT,
                LayoutParams.WRAP_CONTENT
            )
            visibility = GONE // Start as invisible
            addView(this)
        }

        // Initialize with default background
        updateBackgroundForState()
    }

    /**
     * Set background resources for different states
     */
    fun setStateBackgrounds(
        @DrawableRes normal: Int,
        @DrawableRes selected: Int,
        @DrawableRes activated: Int,
        @DrawableRes disabled: Int
    ) {
        normalBackground = normal
        selectedBackground = selected
        activatedBackground = activated
        disabledBackground = disabled
        updateBackgroundForState()
    }

    /**
     * Configure the list row with data
     */
    fun configure(
        title: CharSequence,
        subtitle: CharSequence? = null,
        iconText: CharSequence? = null // In production, this would be a drawable or image resource
    ) {
        titleTextView.text = title
        subtitleTextView?.text = subtitle
        subtitleTextView?.visibility = if (subtitle.isNullOrEmpty()) GONE else VISIBLE
        iconView?.text = iconText
        iconView?.visibility = if (iconText.isNullOrEmpty()) GONE else VISIBLE
    }

    /**
     * Set selected state
     */
    fun setSelected(selected: Boolean) {
        isSelected = selected
        updateBackgroundForState()
    }

    /**
     * Set activated state (for contextual action mode)
     */
    fun setActivated(activated: Boolean) {
        isActivated = activated
        updateBackgroundForState()
    }

    /**
     * Update background based on current state
     */
    private fun updateBackgroundForState() {
        val background = when {
            isNotEnabled -> disabledBackground
            isActivated -> activatedBackground
            isSelected -> selectedBackground
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

    /**
     * Get the title text
     */
    fun getTitle(): CharSequence {
        return titleTextView.text
    }

    /**
     * Get the subtitle text
     */
    fun getSubtitle(): CharSequence? {
        return subtitleTextView?.text
    }

    /**
     * Check if row is selected
     */
    fun isSelected(): Boolean {
        return isSelected
    }

    /**
     * Check if row is activated
     */
    fun isActivated(): Boolean {
        return isActivated
    }
}