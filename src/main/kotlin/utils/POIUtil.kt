/**
 * Copyright (c) 2025 LuminaPJ
 * SM2 Key Generator is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
package org.lumina.utils

import kotlinx.datetime.toJavaLocalDateTime
import org.apache.commons.io.output.ByteArrayOutputStream
import org.apache.poi.ss.usermodel.*
import org.apache.poi.xssf.usermodel.XSSFWorkbook
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlinx.datetime.LocalDateTime as KotlinLocalDateTime

object POIUtil {
    /**
     * 创建 Excel 文件
     * @param sheets 包含工作表名称和数据的映射
     * @return Excel 文件的字节数组
     */
    fun createExcel(sheets: Map<String, List<List<Any?>>>): ByteArray {
        val workbook = XSSFWorkbook()
        try {
            // 创建标题样式（用于表头）
            val headerStyle = workbook.createCellStyle()
            val headerFont = workbook.createFont()
            headerFont.bold = true
            headerFont.fontHeightInPoints = 12.toShort()
            headerFont.fontName = "微软雅黑"
            headerStyle.setFont(headerFont)
            headerStyle.fillForegroundColor = IndexedColors.GREY_25_PERCENT.index
            headerStyle.fillPattern = FillPatternType.SOLID_FOREGROUND
            headerStyle.alignment = HorizontalAlignment.CENTER
            headerStyle.verticalAlignment = VerticalAlignment.CENTER
            headerStyle.setBorderTop(BorderStyle.THIN)
            headerStyle.setBorderRight(BorderStyle.THIN)
            headerStyle.setBorderBottom(BorderStyle.THIN)
            headerStyle.setBorderLeft(BorderStyle.THIN)
            headerStyle.topBorderColor = IndexedColors.GREY_50_PERCENT.index
            headerStyle.rightBorderColor = IndexedColors.GREY_50_PERCENT.index
            headerStyle.bottomBorderColor = IndexedColors.GREY_50_PERCENT.index
            headerStyle.leftBorderColor = IndexedColors.GREY_50_PERCENT.index

            // 创建数据样式
            val dataStyle = workbook.createCellStyle()
            val dataFont = workbook.createFont()
            dataFont.fontHeightInPoints = 11.toShort()
            dataFont.fontName = "微软雅黑"
            dataStyle.setFont(dataFont)
            dataStyle.alignment = HorizontalAlignment.CENTER
            dataStyle.verticalAlignment = VerticalAlignment.CENTER
            dataStyle.setBorderTop(BorderStyle.THIN)
            dataStyle.setBorderRight(BorderStyle.THIN)
            dataStyle.setBorderBottom(BorderStyle.THIN)
            dataStyle.setBorderLeft(BorderStyle.THIN)
            dataStyle.topBorderColor = IndexedColors.GREY_50_PERCENT.index
            dataStyle.rightBorderColor = IndexedColors.GREY_50_PERCENT.index
            dataStyle.bottomBorderColor = IndexedColors.GREY_50_PERCENT.index
            dataStyle.leftBorderColor = IndexedColors.GREY_50_PERCENT.index

            // 创建标题样式（用于任务详情等标签列）
            val titleStyle = workbook.createCellStyle()
            val titleFont = workbook.createFont()
            titleFont.bold = true
            titleFont.fontHeightInPoints = 11.toShort()
            titleFont.fontName = "微软雅黑"
            titleStyle.setFont(titleFont)
            titleStyle.alignment = HorizontalAlignment.RIGHT
            titleStyle.verticalAlignment = VerticalAlignment.CENTER
            titleStyle.setBorderTop(BorderStyle.THIN)
            titleStyle.setBorderRight(BorderStyle.THIN)
            titleStyle.setBorderBottom(BorderStyle.THIN)
            titleStyle.setBorderLeft(BorderStyle.THIN)
            titleStyle.topBorderColor = IndexedColors.GREY_50_PERCENT.index
            titleStyle.rightBorderColor = IndexedColors.GREY_50_PERCENT.index
            titleStyle.bottomBorderColor = IndexedColors.GREY_50_PERCENT.index
            titleStyle.leftBorderColor = IndexedColors.GREY_50_PERCENT.index
            titleStyle.fillForegroundColor = IndexedColors.GREY_40_PERCENT.index
            titleStyle.fillPattern = FillPatternType.SOLID_FOREGROUND

            // 创建标题行样式（用于"任务详情"等主标题行）
            val mainTitleStyle = workbook.createCellStyle()
            val mainTitleFont = workbook.createFont()
            mainTitleFont.bold = true
            mainTitleFont.fontHeightInPoints = 16.toShort()
            mainTitleFont.fontName = "微软雅黑"
            mainTitleStyle.setFont(mainTitleFont)
            mainTitleStyle.alignment = HorizontalAlignment.CENTER
            mainTitleStyle.verticalAlignment = VerticalAlignment.CENTER

            sheets.forEach { (sheetName, sheetData) ->
                val sheet = workbook.createSheet(sheetName)

                sheetData.forEachIndexed { rowIndex, rowData ->
                    val row = sheet.createRow(rowIndex)
                    rowData.forEachIndexed { cellIndex, cellData ->
                        val cell = row.createCell(cellIndex)

                        // 根据数据类型设置值
                        when (cellData) {
                            is String -> cell.setCellValue(cellData)
                            is Number -> cell.setCellValue(cellData.toDouble())
                            is Boolean -> cell.setCellValue(if (cellData) "是" else "否")
                            is LocalDateTime -> cell.setCellValue(cellData.format(DateTimeFormatter.ofPattern("yyyy年MM月dd日 HH:mm:ss")))
                            is KotlinLocalDateTime -> cell.setCellValue(
                                cellData.toJavaLocalDateTime()
                                    .format(DateTimeFormatter.ofPattern("yyyy年MM月dd日 HH:mm:ss"))
                            )

                            null -> cell.setCellValue("")
                            else -> cell.setCellValue(cellData.toString())
                        }

                        // 应用样式
                        if (rowIndex == 0 && sheetData.size > 1 && sheetData[0].size > 1) {
                            // 表头行
                            cell.cellStyle = headerStyle
                        } else if (sheetData.isNotEmpty() && sheetData[0].size == 2 && cellIndex == 0) {
                            // 第一列（标签列）
                            cell.cellStyle = titleStyle
                        } else {
                            // 数据行
                            cell.cellStyle = dataStyle
                        }
                    }
                }

                // 自动调整列宽
                if (sheetData.isNotEmpty()) {
                    val columnCount = sheetData.maxOfOrNull { it.size } ?: 0
                    for (i in 0 until columnCount) {
                        sheet.autoSizeColumn(i)
                        // 设置最小列宽
                        val columnWidth = sheet.getColumnWidth(i)
                        if (columnWidth < 20 * 256) {
                            sheet.setColumnWidth(i, 20 * 256) // 最小20个字符宽度
                        }
                        // 设置最大列宽
                        if (columnWidth > 50 * 256) {
                            sheet.setColumnWidth(i, 50 * 256) // 最大50个字符宽度
                        }
                    }
                }
            }

            val outputStream = ByteArrayOutputStream()
            workbook.use { wb -> wb.write(outputStream) }

            return outputStream.toByteArray()
        } finally {
            workbook.close()
        }
    }

    /**
     * 创建带表头的 Excel 工作表数据
     * @param headers 表头列表
     * @param dataRows 数据行列表
     * @return 包含表头和数据的完整列表
     */
    fun createSheetDataWithHeaders(headers: List<String>, dataRows: List<List<Any?>>): List<List<Any?>> {
        val result = mutableListOf<List<Any?>>()
        result.add(headers)
        result.addAll(dataRows)
        return result
    }

    /**
     * 添加生成时间信息到工作表数据
     * @param sheetData 原始工作表数据
     * @return 添加了生成时间信息的工作表数据
     */
    fun addGeneratedInfo(sheetData: MutableList<List<Any?>>): List<List<Any?>> {
        val generatedAt = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy年MM月dd日 HH:mm:ss"))
        sheetData.add(listOf("此 Excel 文件生成时间", generatedAt))
        return sheetData
    }
}